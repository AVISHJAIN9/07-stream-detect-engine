# 05 Data Model: Streaming Detection Engine (Sigma DSL)

## 1. Specification Overview [Specified]
Real-time stream processing detection engine with Sigma-style rule DSL, Aho-Corasick matching, and out-of-order event watermarks.

## 2. Core Mechanisms [Specified]
DSL parser and AST compiler, shared predicate evaluation, Aho-Corasick multi-pattern search, sliding and tumbling windows, keyed state with TTL eviction, event-time processing with watermarks, alert deduplication, rule hot-reload, backpressure.

## 3. Unknowns & Benchmarks
All performance numbers, throughput rates, and latency figures are marked **TO BE MEASURED** until run on standard hardware.
