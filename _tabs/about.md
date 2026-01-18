---
title: About
icon: fas fa-info-circle
order: 4
---

> Fast code is easy. Code you can trust takes work.

I'm Salvatore, and I spend my days figuring out how to store more data in less space while keeping queries and indexing fast. But what really drives me is a deeper question: how do you build systems you can trust?

I like understanding systems well enough that I can change them safely, measure the impact, and sleep at night.

I believe code that can't be tested can't be trusted, and code that can't be trusted can't be changed safely. This isn't just a preference. It's the lens through which I evaluate every design decision. When I look at a system, I ask: can I prove it works? Can I measure it? Can someone else change it safely?

![Turin, Italy](/assets/images/matteo-giallongo-yTn8ueddb_A-unsplash.jpg){: .rounded-10 }
_Turin, Italy. Photo by [Matteo Giallongo](https://unsplash.com/@matteogiallongo) on Unsplash._

Currently, I work on the storage engine at [Elastic](https://elastic.co), focusing on time series, metrics, and observability workloads. The kind of data that arrives by the billions and needs to stick around for months. My job is making that economically viable through better compression, smarter indexing, and questioning assumptions about how things have always been done.

The work I'm proudest of isn't measured primarily in pull requests or percentage improvements, though those exist. It's the compression techniques (delta encoding, GCD, bit-packing) that turned expensive storage problems into tractable ones. When a 100TB cluster costs $60-80K less per year to operate, that's not just an optimization. That's the difference between a feature being viable and being shelved.

---

My path here was anything but direct, but looking back, every stop taught me something I still use.

I started in embedded systems, writing safety-critical code where every byte mattered and a bug could mean something actually dangerous. Automotive mostly: autonomous driving at TomTom, Apple CarPlay and Android Auto drivers at Magneti Marelli, CAN diagnostics tools. This is where I learned that testability isn't a nice-to-have. It's how you sleep at night when your code controls a vehicle.

My obsession with testability actually comes from electronics and VLSI, where Design for Testability (DFT) is a discipline. You add features during design specifically to make post-manufacture testing easier, faster, and more thorough. Find defects early, reduce costs. The same principle applies to software, but somehow most of the industry hasn't internalized it. Code that wasn't designed for testability becomes code that nobody wants to touch. That frustrates me more than almost anything else in this field.

Then payments at Adyen, where I built the second version of their Intelligent Payment Router. Different domain, same obsession: making the right decision, fast, at scale, and being able to prove it works.

![Amsterdam, Netherlands](/assets/images/jonne-makikyro-knbve9xxH4U-unsplash.jpg){: .rounded-10 }
_Amsterdam. Where I learned that correctness at scale is a systems problem, not a testing problem. Photo by [Jonne Mäkikyrö](https://unsplash.com/@jonne_makikyro) on Unsplash._

A stint at King taught me what "high throughput" really means when millions of people are playing games simultaneously.

![Barcelona, Spain](/assets/images/dorian-d1-aX5NLrKgRBc-unsplash.jpg){: .rounded-10 }
_Barcelona. Where "millions of concurrent users" stopped being an abstraction. Photo by [Dorian Mongel](https://unsplash.com/@dorian_d1) on Unsplash._

Eventually I found my way to Lucene and Elasticsearch, and something clicked. Search and storage sit at this intersection of computer science fundamentals and practical engineering that I find endlessly interesting. You need to understand data structures, compression theory, and distributed systems, but you also need to ship code that works in production. Theory that survives contact with reality.

I spent eight months at Weaviate working on their vector database core, picking up Go and learning that different languages have different philosophies but the hard problems are the same: how do you make distributed storage reliable and fast? What I enjoyed most was refactoring their replication engine into something testable and modular. Making complex systems understandable is as satisfying to me as making them fast.

Back at Elastic now, because time series compression is a puzzle I'm not done solving.

---

I write this blog for the person I was ten years ago: someone trying to understand how things actually work, frustrated by documentation that assumes too much and tutorials that explain too little.

The posts here are about JVM internals and JIT behavior, storage and compression tricks, Lucene deep dives, and the occasional foray into Go or Rust when Java isn't the right tool. But underneath, they're about a way of thinking: measure before you optimize, question before you accept, and design for testability before you design for anything else.

This blog is where I work through that process in public: understanding systems deeply enough to change them without breaking them.

I'm based in Turin, Italy, working remotely on systems that run everywhere. Find me on [GitHub](https://github.com/salvatore-campagna) or [LinkedIn](https://linkedin.com/in/salvatorecampagna).
