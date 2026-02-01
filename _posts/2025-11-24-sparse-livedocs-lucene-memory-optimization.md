---
title: "When Deletions Are Rare: Rethinking LiveDocs in Lucene"
description: "How a simple observation about deletion patterns led to a memory optimization that benefits nearly every Lucene deployment, and the benchmarking journey to prove it works."
date: 2025-11-24
categories: [Internals, Performance]
tags: [lucene, memory, optimization, search, indexing]
image:
  path: /assets/images/sparse-livedocs-header.jpg
  alt: "Code on a monitor - Photo by Shahadat Rahman on Unsplash"
---

## TL;DR

When a segment has deletions, Lucene allocates one bit per document for `LiveDocs`, even if only a tiny fraction are deleted. A segment with 100 million documents and 0.1% deletions? That's 12MB for a bitset that's 99.9% ones.

[This PR](https://github.com/apache/lucene/pull/15413) introduces adaptive `LiveDocs`: sparse storage for low deletion segments, dense for the rest. No configuration required.

**Two wins:** 8x to 40x memory reduction for segments with few deletions, depending on how deletions are distributed, and deleted-document traversal that scales with the number of deletions, not the segment size.

## How Much Memory Does LiveDocs Actually Use?

You're running a Lucene-based search cluster. Documents get deleted occasionally, maybe 0.1% to 1% of your corpus at any given time. Old versions replaced, spam removed, expired content purged. Nothing dramatic. And in many workloads, deletions cluster together: time-based expiration removes consecutive documents, range deletes hit contiguous IDs.

But let's look at what's happening in memory. Every segment allocates one bit per document for its `LiveDocs` bitset, regardless of how many documents are deleted. A 10 million document segment with 0.1% deletions (10K docs) allocates 1.2MB when only about 160KB is actually needed.

For a 100 million document segment the numbers scale accordingly: about 12MB allocated for a bitset that could fit in a fraction of that.

For a typical deployment with dozens of segments and deletion rates under 1%, you're burning megabytes of heap on data structures that are 99% ones.

This is the kind of waste that bothers me. Let's see if we can do better.

## What is LiveDocs?

Let's remind ourselves how deletion works in Lucene.

Why doesn't Lucene just remove deleted documents from the segment? The obvious answer would be "just delete the data." But think about what that means: rewriting the segment, updating all the internal offsets, invalidating any readers currently using it. That's expensive and breaks concurrent access.

Lucene's answer is simpler: segments are immutable. That immutability is what makes concurrent reads fast and lock-free. So instead of removing data, Lucene marks the document as deleted in a per-segment bitset called **LiveDocs**[^livedocs]: one bit per document, where 1 means live and 0 means deleted.

> Segment immutability is a foundational design choice in Lucene. It eliminates the need for read locks, enables safe concurrent access from multiple threads, and simplifies crash recovery. `LiveDocs` exists because of this choice: you can't modify a segment, so you mark deletions separately.
{: .prompt-tip }

`LiveDocs` only exists when a segment has deletions. A freshly written segment has no `.liv` file at all, and every document is implicitly live. Once deletions appear, `LiveDocs` shows up on almost every read path: queries filter through it to skip deleted hits, merges[^merges] consult it when copying survivors into new segments[^soft-deletes], and aggregations need it to keep facet counts and statistics accurate (more on this later). The deleted document's data remains in the segment until a merge physically removes it. Mark now, reclaim space later.

In memory, `LiveDocs` is traditionally a `FixedBitSet`, which allocates one bit per document regardless of how many are deleted. That's the waste we're addressing.

## What If We Only Stored the Deleted IDs?

The optimization comes from a simple observation: **most segments have very few deletions**.

> In append-heavy workloads, segments often reach tens of millions of documents with deletion rates well under 1%. When your data structure is 99.9% ones, you're paying for generality you don't need.
{: .prompt-tip }

In practice, deletion rates are typically well under 1%. Documents get updated, old content expires, duplicates get removed. You're rarely deleting a large fraction of your index at once. But if that's the case, what if we stored only the deleted document IDs instead of a bit for every document?

As a baseline, imagine we stored deleted document IDs in a simple 32-bit int array:

```
Dense (current):  maxDoc / 8 bytes
Sparse (baseline): deletedCount * 4 bytes  (32-bit int[])

Crossover point: maxDoc/8 = deletedCount * 4
                 deletedCount = maxDoc/32
                 deletionRate = 1/32 ≈ 3.125%
```

So even with this naive approach, sparse wins for anything under about 3% deletions.

But the `int[]` model is a conservative baseline. The real implementation uses [`SparseFixedBitSet`](https://lucene.apache.org/core/5_2_1/core/org/apache/lucene/util/SparseFixedBitSet.html), a block-based sparse bitset that is more space-efficient than a plain array of document IDs. Because `SparseFixedBitSet` uses less memory than the baseline model predicts, the true crossover point (where sparse and dense use equal memory) is likely higher than 3%. The 1% threshold used in practice is a deliberately conservative design choice, ensuring consistent wins across all deletion patterns without risking regressions in adversarial cases.

`SparseFixedBitSet` divides the bit space into 4096-bit blocks and only allocates blocks that contain at least one set bit. Within each block, only the non-zero longs are stored. This means clustered deletions pack tightly into shared blocks, making the representation even smaller than the naive per-ID estimate.

See [the implementation](https://github.com/apache/lucene/pull/15413) for the full details.

## How Does the Implementation Work?

The fix introduces two implementations behind a common `LiveDocs` interface:

| Implementation | When Used | Storage |
|----------------|-----------|---------|
| **SparseLiveDocs** | ≤1% deletions | Block-sparse bitset (`SparseFixedBitSet`) |
| **DenseLiveDocs** | >1% deletions | Traditional `FixedBitSet` |

As segments accumulate deletions over time, the appropriate implementation is selected when `LiveDocs` is materialized for a reader, based on the current deletion density. No configuration needed.

```java
// Simplified view of the selection logic
LiveDocs loadLiveDocs(int maxDoc, int deletedCount) {
    double deletionRate = (double) deletedCount / maxDoc;

    if (deletionRate <= 0.01) {  // 1% threshold
        return SparseLiveDocs.build(deletedDocIds, maxDoc);
    } else {
        return DenseLiveDocs.build(liveBits, maxDoc);
    }
}
```

### Why 1% and Not 3%?

The math says we break even around 3%, so why use 1%? Let's look at what happens near the crossover:

```
At 2% deletions (10M docs):
  Dense:  1.2MB
  Sparse: 200K docs × 4 bytes = 800KB
  Winner: Sparse (1.5x better)

At 3% deletions (10M docs):
  Dense:  1.2MB
  Sparse: 300K docs × 4 bytes = 1.2MB
  Winner: Tie

At 4% deletions (10M docs):
  Dense:  1.2MB
  Sparse: 400K docs × 4 bytes = 1.6MB
  Winner: Dense
```

The 1% threshold provides a comfortable margin. We're guaranteed at least 3x memory savings whenever sparse kicks in. No edge cases, no close calls.

### What About JVM Overhead?

The math above is simplified. In reality, both `FixedBitSet` and `SparseFixedBitSet` carry JVM object headers, array overhead, and potential alignment padding. Including these, the actual crossover point shifts slightly, but the 1% threshold remains safe.[^naive-model] The benchmarks use `ramBytesUsed()`, which accounts for object headers and array sizes but doesn't capture every JVM detail. The reported savings are close to real-world usage, though actual footprint may differ slightly depending on JVM configuration.

### What Happens When Deletes Occur After a Segment Is Loaded?

`LiveDocs` is immutable from the reader's perspective. When deletes occur, Lucene does not mutate the `LiveDocs` instance held by already-open readers. Instead, deletes become visible when a reader is refreshed, at which point a new `LiveDocs` snapshot is materialized.

Existing readers continue to see a consistent view of the segment. New readers observe the updated deletions. Because `LiveDocs` is never mutated after creation, multiple search threads can check it concurrently without synchronization. The choice between sparse and dense `LiveDocs` is made when this snapshot is created, based on the current deletion density.

In practice, segments that accumulate many deletions are often merged away, so most segments stay in the low-deletion regime where sparse storage applies.

## What Does the API Look Like?

The key design decision was creating a proper `LiveDocs` interface that extends `Bits`:

```java
public interface LiveDocs extends Bits {
    /** Iterate over live documents */
    DocIdSetIterator liveDocsIterator();

    /** Iterate over deleted documents (the interesting part) */
    DocIdSetIterator deletedDocsIterator();

    /** Number of deleted documents */
    int deletedCount();
}
```

The `deletedDocsIterator()` method is where sparse really shines. With dense storage, iterating over deleted documents means scanning millions of bits looking for zeros. With sparse storage, you just iterate the array.

So far this sounds like a memory optimization. But it turns out iteration speed matters just as much, and here's why.

## Why Does Iterating Deleted Documents Matter?

This might seem like an obscure capability, but it unlocks a powerful optimization pattern for aggregations.

**The traditional approach**: When computing aggregations (histograms, facet counts, statistics) over a segment, you need to exclude deleted documents. This means checking `LiveDocs` for every document you process. For a segment with 10 million documents and 0.1% deletions, you're doing 10 million bit lookups to skip 10,000 documents.

**The optimized approach**: What if you computed the aggregation as if no documents were deleted, then corrected for deletions afterward?

```
1. Compute aggregation over ALL documents (fast, no `LiveDocs` checks)
2. Iterate ONLY deleted documents
3. Subtract their contributions from the result
```

This flips the complexity from `O(maxDoc)` to `O(deletedDocs)`. For that 10 million document segment with 0.1% deletions, you go from 10 million operations to 10,000.

But here's the catch: step 2 requires iterating over deleted documents efficiently. With a dense `FixedBitSet`, you'd scan all 10 million bits looking for zeros, which defeats the purpose. With `SparseLiveDocs`, you iterate only the 10,000 deleted documents.

But how does a caller know when this is actually worth doing? The iterator's `cost()` tells you. With `SparseLiveDocs`, cost is the deleted count, so you're iterating a small set. With `DenseLiveDocs`, cost is `maxDoc`, which means you'd be scanning every bit and defeating the purpose.

```java
DocIdSetIterator deletedDocs = liveDocs.deletedDocsIterator();
if (deletedDocs.cost() < maxDoc / 4) {
    // Correction approach: compute over all docs, then subtract deletions
} else {
    // Traditional approach: filter deleted docs during the main pass
}
```

Why not just throw an exception when dense iteration would be slow? Because slow and correct beats surprising. Both implementations honor the full `LiveDocs` interface, and `cost()` is already how Lucene handles this everywhere: query planning, intersection strategies, scorer selection. Callers check cost, pick a strategy, move on. No type-checking, no try-catch. You don't need to know which implementation you're talking to.

> `cost()` itself is `O(1)`, both `SparseLiveDocs` and `DenseLiveDocs` precompute it at construction time. The decision of which strategy to use adds no overhead to the query path.
{: .prompt-tip }

This pattern is particularly valuable for histogram corrections in numeric aggregations, facet count adjustments in search results, and additive statistics like sum, count, and average.

**Where this doesn't apply**: The "compute then correct" pattern requires the aggregation to be reversible. For example, you can subtract a deleted document's value from a sum, but you can't "un-insert" it from a HyperLogLog cardinality estimate or remove its influence on a percentile sketch. Percentiles, cardinality estimates, and scripted aggregations can't use this approach. For those, you still need to filter deleted documents during the main pass.

The related work on [sparse `LiveDocs` for deletions](https://github.com/apache/lucene/issues/13084) and [efficient iteration over deleted doc values](https://github.com/apache/lucene/issues/15226) explores these aggregation optimizations in detail.

## Does It Actually Work? Let's Measure.

I'm not one to ship optimizations without numbers. [The PR](https://github.com/apache/lucene/pull/15413) includes JMH benchmarks across different segment sizes and deletion patterns. Here's the setup:

```java
@State(Scope.Benchmark)
public class LiveDocsBenchmark {
    @Param({"100000", "1000000", "10000000"})
    int maxDoc;

    @Param({"0.001", "0.01", "0.05", "0.10", "0.20", "0.30"})
    double deletionRate;

    @Param({"RANDOM", "CLUSTERED", "UNIFORM"})
    String deletionPattern;
}
```

Three segment sizes, six deletion rates, three deletion patterns: 54 combinations total. The results we focus on here are memory footprint, measured via `ramBytesUsed()` and reported as a JMH auxiliary counter alongside timing results. Let's see what we found.

### How Much Memory Do We Save?

For a 10 million document segment, here's what the benchmarks show:

| Deletion Rate | Pattern | Dense Memory | Sparse Memory | Reduction |
|---------------|---------|--------------|---------------|-----------|
| 0.1% | Random | ~1.2MB | ~160KB | **~7.6x** |
| 0.1% | Clustered | ~1.2MB | ~30KB | **~40x** |
| 1.0% | Random | ~1.2MB | ~800KB | **~1.6x** |
| 1.0% | Clustered | ~1.2MB | ~42KB | **~29x** |

*Benchmarked up to 10M docs; larger segments are expected to scale proportionally.*

Clustered deletions are common in practice: time-based expiration removes consecutive documents, range deletes hit contiguous IDs. In these cases `SparseFixedBitSet` packs deleted IDs into shared blocks, which is why the reduction is so dramatic.

The memory savings are only part of the story. As discussed earlier, sparse storage also makes iterating deleted documents `O(deletedDocs)` rather than `O(maxDoc)`, which is what enables the "compute then correct" pattern for aggregations.

### What's the Worst Case?

What about adversarial scenarios? As an intentional stress test, I benchmarked maximally scattered deletions at about 1.5%: above the 1% threshold, so we fall back to dense storage. The memory overhead is about 5.5% across segment sizes from 10M to 100M docs, coming entirely from the new wrapper objects. Even in this worst case, deleted-document iteration benefits from the refactored `FilteredDocIdSetIterator`, which applies to both representations.

So there are actually two optimizations here: sparse storage for memory (when deletions are rare), and better iteration (always).

> This PR delivers two independent wins. Sparse storage reduces memory when deletions are rare. The refactored iteration using `FilteredDocIdSetIterator` speeds up deleted-document traversal for both sparse and dense representations. Even if your segments never qualify for sparse storage, you still get faster iteration.
{: .prompt-tip }

## What Does This Mean in Production?

Consider a typical large scale deployment with 1000 segments across shards, 10 million average documents per segment, and a 0.5% average deletion rate.

**Before**: 1000 × about 1.2MB = around 1.2GB of `LiveDocs` memory

**After**: 1000 × about 500KB = around 500MB of `LiveDocs` memory

That's hundreds of megabytes of heap freed up for more useful things: larger query caches, bigger I/O buffers, or simply fewer GC pauses from reduced heap pressure.

## Conclusion

`LiveDocs` is consulted on every search hit and iterated during certain aggregations. When deletions are rare, storing one bit per document wastes memory and forces full scans to find very few deleted entries.

The solution is simple: use sparse storage when deletions are rare, dense storage when they are not. The 1% threshold ensures the switch only happens when the benefit is clear. The result is 8x to 40x less memory for low-deletion segments depending on deletion patterns. Deleted-document iteration scales with the number of deletions rather than the size of the segment. No API changes, no configuration required.

The optimization is purely in-memory. Segments still write the standard Lucene90 format, and the `Bits` interface continues working exactly as before.[^sparse-disk] Existing code that calls `liveDocs.get(docId)` sees no change. The new `LiveDocs` interface is opt-in for code that wants efficient deleted document iteration.

Sometimes the best optimizations come from noticing what isn't there. A bitset that's 99.9% ones is barely a bitset at all.
## Resources

- [Sparse LiveDocs PR](https://github.com/apache/lucene/pull/15413): The implementation with full discussion
- [SparseFixedBitSet](https://lucene.apache.org/core/5_2_1/core/org/apache/lucene/util/SparseFixedBitSet.html): Block-sparse bitset used for low-deletion segments
- [FixedBitSet](https://lucene.apache.org/core/9_0_0/core/org/apache/lucene/util/FixedBitSet.html): Dense bitset used for high-deletion segments
- [Lucene Codec Documentation](https://lucene.apache.org/core/9_0_0/core/org/apache/lucene/codecs/package-summary.html): How Lucene stores segment metadata

[^merges]: Lucene periodically combines multiple smaller segments into larger ones. This process, called [merging](https://lucene.apache.org/core/9_0_0/core/org/apache/lucene/index/MergePolicy.html), is when deleted documents are physically removed and disk space is reclaimed.

[^sparse-disk]: A future codec version could write sparse deletions natively to disk, eliminating the dense-to-sparse conversion on load and reducing `.liv` file sizes for low-deletion segments. This would require a format change, so it was kept out of scope for this PR.

[^naive-model]: These numbers use the simplified `deletedCount × 4 bytes` model from above. The actual `SparseFixedBitSet` has higher per-entry overhead due to its block structure. For example, at 1% deletions the benchmark measures 804KB rather than the 400KB this model predicts. The real crossover point is therefore lower than 3%, which makes the conservative 1% threshold even more appropriate.

[^livedocs]: The [`LiveDocs`](https://github.com/apache/lucene/blob/main/lucene/core/src/java/org/apache/lucene/util/LiveDocs.java) interface extends `Bits` and was introduced in [this PR](https://github.com/apache/lucene/pull/15413) as part of this work. Prior to this change, `LiveDocs` was simply a `FixedBitSet` implementing `Bits`, with no dedicated interface.

[^soft-deletes]: This applies to *hard* deletes. Lucene also supports [*soft* deletes](https://lucene.apache.org/core/8_0_0/core/org/apache/lucene/index/SoftDeletesRetentionMergePolicy.html), which are tracked via a DocValues field rather than `LiveDocs`. Soft-deleted documents may survive merges depending on the configured [`SoftDeletesRetentionMergePolicy`](https://lucene.apache.org/core/8_0_0/core/org/apache/lucene/index/SoftDeletesRetentionMergePolicy.html) and retention query. Elasticsearch uses soft deletes for [operations history and cross-cluster replication](https://github.com/elastic/elasticsearch/issues/29530).
