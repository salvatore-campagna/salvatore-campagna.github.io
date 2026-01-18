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

When a segment has deletions, Lucene allocates one bit per document for LiveDocs — even if only a tiny fraction are deleted. A segment with 100 million documents and 0.1% deletions? That's 12MB for a bitset that's 99.9% ones.

[This PR](https://github.com/apache/lucene/pull/15413) introduces adaptive LiveDocs: sparse storage for low deletion segments, dense for the rest. No configuration required.

**Two wins:**
- **Memory**: Up to 40x reduction for segments with few deletions
- **Iteration**: Up to 30x faster when iterating deleted documents

## How Much Memory Does LiveDocs Actually Use?

You're running a Lucene-based search cluster. Documents get deleted occasionally, maybe 0.1% to 1% of your corpus at any given time. Old versions replaced, spam removed, expired content purged. Nothing dramatic. And in many workloads, deletions cluster together: time-based expiration removes consecutive documents, range deletes hit contiguous IDs.

But let's look at what's happening in memory. Every segment allocates one bit per document for its LiveDocs bitset, regardless of how many documents are deleted:

| Segment Size | LiveDocs Memory | Typical Deletions | Actually Needed |
|--------------|-----------------|-------------------|-----------------|
| 10 million docs | 1.2MB | 0.1% (10K docs) | ~40KB |
| 100 million docs | 12MB | 0.1% (100K docs) | ~400KB |

For a typical deployment with dozens of segments and deletion rates under 1%, you're burning megabytes of heap on data structures that are 99% ones.

This is the kind of waste that bothers me. Let's see if we can do better.

## What is LiveDocs?

Let's remind ourselves how deletion works in Lucene.

Why doesn't Lucene just remove deleted documents from the segment? The obvious answer would be "just delete the data." But think about what that means: rewriting the segment, updating all the internal offsets, invalidating any readers currently using it. That's expensive and breaks concurrent access.

Lucene's answer is simpler: segments are immutable. That immutability is what makes concurrent reads fast and lock-free. So instead of removing data, Lucene marks the document as deleted in a per-segment bitset called **LiveDocs**: one bit per document, where 1 means live and 0 means deleted.

When does LiveDocs exist? Only when a segment has deletions. A freshly written segment has no `.liv` file at all, and every document is implicitly live.

Where does LiveDocs get checked?

- **Search**: Effectively every query filters through LiveDocs. If the bit is 0, the document is skipped.
- **Merge**: This is when deleted documents are physically removed. The merge process iterates LiveDocs to decide which documents to copy to the new segment.[^soft-deletes]
- **Aggregations**: Facet counts and statistics need to exclude deleted documents (more on this later).

Why "two-phase deletion"? The deleted document's data (stored fields, doc values) remains in the segment until a merge removes it. Mark now, reclaim space later.

In memory, LiveDocs is traditionally a `FixedBitSet`, which allocates one bit per document regardless of how many are deleted. That's the waste we're addressing.

## What If We Only Stored the Deleted IDs?

The optimization comes from a simple observation: **most segments have very few deletions**.

In practice, deletion rates are typically well under 1%. Documents get updated, old content expires, duplicates get removed. You're rarely deleting a large fraction of your index at once.

What if we stored only the deleted document IDs instead of a bit for every document? (Why deleted and not live? Because at low deletion rates, there are far fewer deleted IDs to store.)

As a baseline, imagine we stored deleted doc IDs in a simple 32-bit int array:

```
Dense (current):  maxDoc / 8 bytes
Sparse (baseline): deletedCount * 4 bytes  (32-bit int[])

Crossover point: maxDoc/8 = deletedCount * 4
                 deletedCount = maxDoc/32
                 deletionRate = 1/32 ≈ 3.125%
```

So even with this naive approach, sparse wins for anything under ~3% deletions.

But the `int[]` model is a conservative baseline. The real implementation uses [`SparseFixedBitSet`](https://lucene.apache.org/core/5_2_1/core/org/apache/lucene/util/SparseFixedBitSet.html), a block-based sparse bitset that is more space-efficient than a plain array of document IDs. Because `SparseFixedBitSet` uses less memory than the baseline model predicts, the true crossover point—where sparse and dense use equal memory—is likely higher than 3%. The 1% threshold used in practice is a deliberately conservative design choice, ensuring consistent wins across all deletion patterns without risking regressions in adversarial cases.

**How `SparseFixedBitSet` stays small:**
- Divides the bit space into 4096-bit blocks (64 longs per block)
- Only materializes blocks that contain at least one set bit
- Within each block, only stores the non-zero longs
- Deletions that cluster together (common in time-series or batch updates) share blocks, further reducing overhead

See [the implementation](https://github.com/apache/lucene/pull/15413) for the full details.

## How Does the Implementation Work?

The fix introduces two implementations behind a common `LiveDocs` interface:

| Implementation | When Used | Storage |
|----------------|-----------|---------|
| **SparseLiveDocs** | ≤1% deletions | Block-sparse bitset (`SparseFixedBitSet`) |
| **DenseLiveDocs** | >1% deletions | Traditional `FixedBitSet` |

As segments accumulate deletions over time, the format reader automatically selects the right implementation based on deletion density when loading a segment. No configuration needed.

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

The math above is simplified. In reality, both representations have overhead:

- **Dense**: `FixedBitSet` has object headers (~16 bytes) and the backing `long[]` has its own header and potential padding
- **Sparse**: The `SparseFixedBitSet` has its own object and block-array overhead

Including JVM object headers and alignment, the actual crossover point shifts slightly, but the 1% threshold remains safe. The benchmarks reflect practical JVM object footprint rather than theoretical byte counts, so the reported savings are representative of real-world memory usage.

## What's the API Look Like?

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

**The traditional approach**: When computing aggregations (histograms, facet counts, statistics) over a segment, you need to exclude deleted documents. This means checking LiveDocs for every document you process. For a segment with 10 million documents and 0.1% deletions, you're doing 10 million bit lookups to skip 10,000 documents.

**The optimized approach**: What if you computed the aggregation as if no documents were deleted, then corrected for deletions afterward?

```
1. Compute aggregation over ALL documents (fast, no LiveDocs checks)
2. Iterate ONLY deleted documents
3. Subtract their contributions from the result
```

This flips the complexity from O(maxDoc) to O(deletedDocs). For that 10 million document segment with 0.1% deletions, you go from 10 million operations to 10,000.

But here's the catch: step 2 requires iterating over deleted documents efficiently. With a dense `FixedBitSet`, you'd scan all 10 million bits looking for zeros, which defeats the purpose. With `SparseLiveDocs`, you iterate only the 10,000 deleted documents.

This pattern is particularly valuable for:
- **Histogram corrections** in numeric aggregations
- **Facet count adjustments** in search results
- **Additive statistics** (sum, count, average)

**Where this doesn't apply**: The "compute then correct" pattern requires the aggregation to be reversible. Percentiles, cardinality estimates, scripted aggregations, and operations with document-level side effects can't use this approach. For those, you still need to filter deleted documents during the main pass.

The related work in [Lucene #13084](https://github.com/apache/lucene/issues/13084) and [#15226](https://github.com/apache/lucene/issues/15226) explores these aggregation optimizations in detail.

## Does It Actually Work? Let's Measure.

I'm not one to ship optimizations without numbers. [The PR](https://github.com/apache/lucene/pull/15413) includes JMH benchmarks across different segment sizes and deletion patterns. Here's the setup:

```java
@State(Scope.Benchmark)
public class LiveDocsBenchmark {
    @Param({"1000000", "10000000", "100000000"})
    int maxDoc;

    @Param({"0.001", "0.01", "0.1"})  // 0.1%, 1%, 10%
    double deletionRate;

    @Param({"RANDOM", "CLUSTERED", "UNIFORM"})
    DeletionPattern pattern;
}
```

Three segment sizes, three deletion rates, three deletion patterns: 27 combinations total. The results focus on two things: memory footprint and deleted-document iteration speed. Let's see what we found.

### Memory Reduction

For a 10 million document segment, sparse storage cuts memory from 1.2MB to 160KB at 0.1% deletions (7.6x reduction) and to 760KB at 1% deletions (1.6x reduction). The effect scales with segment size:

| Deletion Rate | Dense Memory | Sparse Memory | Reduction |
|---------------|--------------|---------------|-----------|
| 0.1% | 12MB | ~300KB | **~40x** |
| 1.0% | 12MB | ~2.4MB | **~5x** |

*100 million document segment*

### What About Iteration Speed?

Here's where it gets interesting. Iterating over deleted documents (something you need for certain aggregations and corrections) is dramatically faster:

| Deletion Rate | Dense Iteration | Sparse Iteration | Speedup |
|---------------|-----------------|------------------|---------|
| 0.1% | 31.7ms | 1.0ms | **31.7x** |
| 1.0% | 31.7ms | 8.5ms | **3.7x** |

The dense implementation has to scan every bit. Sparse iterates only the deleted documents.

### What's the Worst Case?

What about adversarial scenarios? As an intentional stress test, I benchmarked maximally scattered deletions: the pattern most hostile to sparse storage.

| Segment Size | Deletion Pattern | Memory Overhead | Iteration Speed |
|--------------|------------------|-----------------|-----------------|
| 10 million docs | Scattered 1.5625% | +5.5% | **4x faster** |
| 100 million docs | Scattered 1.5625% | +3.2% | **4x faster** |

Two things to note here:

1. **Above 1% deletions, we fall back to dense storage.** The slight memory overhead (+5.5%) comes from the new wrapper objects, not from sparse storage being used incorrectly.

2. **Iteration is still 4x faster even with dense storage.** This is a separate win: the PR also refactors how we iterate deleted documents using `FilteredDocIdSetIterator`, which benefits both representations.

So there are actually two optimizations here: sparse storage for memory (when deletions are rare), and better iteration (always). Clustered deletions (common when you delete a range of documents) show even better results: up to **40x** memory reduction because deleted IDs pack tightly.

## What Could Go Wrong?

A few design choices worth highlighting:

### Why Not RoaringBitmap?

A reasonable question. RoaringBitmap is a popular compressed bitmap format that handles sparse data well. But it adds complexity: container management, compression/decompression overhead, and a dependency on external code. For LiveDocs, we need fast random access (`get(docId)`) on every search hit, and we need to integrate with Lucene's existing infrastructure. A simple `int[]` of deleted IDs gives us O(log n) random access via binary search, O(k) iteration, and zero dependencies. At ≤1% deletions, the binary search depth remains small and branch-predictable. In overall benchmark results, no regressions were observed that could be attributed to the representation change. Sometimes the boring solution wins.

### Why No On-Disk Changes?

The optimization is purely in-memory. Segments still write the standard Lucene90 format. On load, we read the dense representation and convert to sparse if the deletion rate is low enough. The conversion overhead is negligible compared to the ongoing memory savings.

### Could This Break Existing Code?

No. The `Bits` interface continues working exactly as before. Existing code that calls `liveDocs.get(docId)` sees no change. The new `LiveDocs` interface is opt-in for code that wants efficient deleted document iteration.

## What Does This Mean in Production?

For a typical large scale deployment:

- 1000 segments across shards
- 10 million average documents per segment
- 0.5% average deletion rate

**Before**: 1000 × 1.2MB = 1.2GB of LiveDocs memory

**After**: 1000 × 200KB = 200MB of LiveDocs memory

That's a gigabyte of heap freed up for more useful things like caching and buffers.

## How Do We Know It Won't Regress?

One thing I'm particularly pleased with is how we validated this. [The PR](https://github.com/apache/lucene/pull/15413) includes:

- **Parameterized benchmarks** covering segment sizes from 100K to 100M documents
- **Multiple deletion patterns**: random, clustered, and uniform
- **Pathological case testing** to ensure no regressions
- **AssertingLiveDocs wrapper** that validates behavior without modifying production code

The benchmarks aren't just "proof it works." They're designed to catch regressions if someone modifies the implementation later. This is DFT thinking applied to software: build testability into the design, not as an afterthought. If you can't measure it, you can't trust it.

## Conclusion

The dense `FixedBitSet` implementation served Lucene well for years. It's simple, predictable, and fast for random access. When deletion rates varied widely and iterating over deleted documents wasn't a common operation, the uniform approach made sense.

What changed? As deployments grew larger and memory pressure increased, the cost of storing mostly-ones bitsets became harder to ignore. Operations that need to iterate deleted documents (like certain aggregations and corrections) benefit from a representation optimized for the common case. The usage patterns evolved, and now the implementation can evolve with them.

By adapting to actual deletion density, we cut memory usage by up to 40x for low-deletion segments while maintaining full compatibility with existing code.

The change ships in a future Lucene release. Your segments will get faster and lighter without you changing a line of code.

## Resources

- [PR #15413: Sparse LiveDocs](https://github.com/apache/lucene/pull/15413): The implementation with full discussion
- [SparseFixedBitSet](https://lucene.apache.org/core/5_2_1/core/org/apache/lucene/util/SparseFixedBitSet.html): Block-sparse bitset used for low-deletion segments
- [FixedBitSet](https://lucene.apache.org/core/9_0_0/core/org/apache/lucene/util/FixedBitSet.html): Dense bitset used for high-deletion segments
- [Lucene Codec Documentation](https://lucene.apache.org/core/9_0_0/core/org/apache/lucene/codecs/package-summary.html): How Lucene stores segment metadata

[^soft-deletes]: This applies to *hard* deletes. Lucene also supports [*soft* deletes](https://lucene.apache.org/core/8_0_0/core/org/apache/lucene/index/SoftDeletesRetentionMergePolicy.html), which are tracked via a DocValues field rather than LiveDocs. Soft-deleted documents may survive merges depending on the configured [`SoftDeletesRetentionMergePolicy`](https://lucene.apache.org/core/8_0_0/core/org/apache/lucene/index/SoftDeletesRetentionMergePolicy.html) and retention query. Elasticsearch uses soft deletes for [operations history](https://github.com/elastic/elasticsearch/issues/29530) and cross-cluster replication.
