# Backbone Vision

This document captures the long-term deployment vision for RustiFlow.

It is not a performance checklist. Use [`docs/performance-roadmap.md`](/home/strgenix/postdoc/projects/rustiflow/docs/performance-roadmap.md)
for execution details and optimization work.

## Goal

The long-term objective is realtime flow reconstruction and feature extraction
at backbone-scale rates:

- `100 Gbit/s`
- `200 Gbit/s`
- `400 Gbit/s`

The target is not only raw throughput. RustiFlow should also remain
operationally attractive:

- low CPU usage relative to captured throughput
- predictable memory usage under burst
- clearly reported overload and drop behavior
- flow and feature semantics that remain trustworthy under realtime load

If RustiFlow can reach those properties, it becomes realistic to propose
deployment on production networks for high-quality dataset collection.

## Near-Term Deployment Path

The immediate deployment ambition is smaller and more concrete:

1. Validate RustiFlow locally at `10 Gbit/s`.
2. Push local validation to `25 Gbit/s` and, if possible, `40 Gbit/s`.
3. Use that evidence to justify deployment on the team's slice of the
   datacenter network.
4. Use datacenter results to support discussions about broader deployment on
   university infrastructure.
5. If RustiFlow proves both efficient and trustworthy there, pursue discussions
   with national ISPs.

This staged path is intentional. It keeps the project grounded in measured
evidence instead of premature scaling claims.

## Why Local `10/25/40G` Matters

Local high-throughput validation is valuable even though it is not identical to
backbone deployment:

- it exposes realtime ingestion bottlenecks early
- it provides repeatable adversarial tests under direct control
- it establishes CPU, memory, and drop-rate baselines before asking operators
  for access to sensitive infrastructure
- it makes later deployment discussions concrete rather than speculative

For RustiFlow, local validation at `10/25/40G` is the proving ground for both
correctness and operational maturity.

## Historical Context

RustiFlow has already been validated at `10 Gbit/s` in the past during earlier
project work with the master's student who produced the original
implementation.

That matters for two reasons:

- this project is not starting from zero on the throughput question
- the current work is a continuation and hardening effort, not a brand-new
  performance ambition

The present goal is to rebuild that confidence on the current codebase, then
extend it beyond the earlier `10 Gbit/s` proof point.

## Technical Implication

The current Linux realtime path is useful for proving semantics, finding
bottlenecks, and achieving moderate-to-high throughput. It should not be
assumed to be the final architecture for `100 Gbit/s+`.

Backbone-scale realtime capture will likely require:

- stronger parallel event ingestion
- tighter control over memory movement and batching
- better core and NUMA locality
- careful flow ownership and sharding design
- possibly a transport path beyond the current ring-buffer-based design if
  measurement shows the present architecture will not scale far enough

This does not reduce the value of the current work. On the contrary, the
current measurement-driven improvements are how RustiFlow can evolve toward a
credible high-rate architecture without sacrificing flow correctness.

## What Operators Will Care About

Whether the audience is a datacenter team, a university backbone team, or a
national ISP, the same practical questions will matter:

- What sustained throughput can RustiFlow handle?
- What packet or event drop rate does it show under realistic and bursty load?
- How many CPU cores does it need per throughput tier?
- How much memory does it require?
- Does overload fail visibly and predictably?
- Are the reconstructed flows and extracted features trustworthy enough for
  dataset generation and network analysis?

RustiFlow should aim to answer those questions with measured data, not only
with architecture claims.

## Success Definition

For this vision, success is not "RustiFlow once hit a very large number in a
lab."

Success is:

- repeatable throughput results
- low and well-characterized resource usage
- clear overload behavior
- stable export semantics
- operator confidence that the tool is safe and useful to deploy

That is the standard required for RustiFlow to move from local experiments to
datacenter use, then to university backbone use, and eventually to ISP-facing
conversations.
