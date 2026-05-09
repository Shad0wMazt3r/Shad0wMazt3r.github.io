---
permalink: /ai-security
title: "The Agent Is Not the Scanner: Making AI Security Agents Better"
excerpt: 'LLMs have gotten surprisingly good at finding vulnerabilities over the past year. These are my notes on building better AI-assisted security workflows, and how different models are impacted by scanners and skills differently.'
author_profile: true
---

## Part I: The Background

Scaffolding an LLM is not a universally good idea. Whether it helps or hurts depends almost entirely on how capable the model already is, and it varies between model families.

I spent eight months running LLMs against security tasks to figure out what actually works and empirically measuring them. The findings were not what I expected.


### Why Raw Agents Felt Wasteful

Handing an agent all the context seems to be a good idea at first glance. 

*Let the AI figure it out*

But that approach has several issues. The first one of which is cost. Why would you spend 20-30K tokens on something that could be easily caught by a scanner? 

Security engineers have worked tirelessly to create scanners and we have effective techniques for SAST and DAST. Moreover, parsing the output for nmap and semgrep outputs is a waste of tokens too. The LLM only needs the most refined results on what has already been looked at, what the results were to steer it towards looking into previously unexplored areas of the application.

### Why Blind Scanners Were Not Enough Either

Writing detection logic for every single vulnerability class/CTF challenge is a fundamentally unsolvable problem considering there would always be vulnerability classes you didn't consider or you didn't expect the specific manifestation in code due to lack of context. Running scans is easy, you can just hit run against a target and wait for the success/fail output but how do you know what to detect and where your vulnerabilities lie?

The deeper problem with scanners and fuzzers are that they are inherently deterministic and only pattern match against known signatures, making them extremely good at finding what to look for but blind to everything else. You may have fully protected yourself against SQLi, XSS, and IDOR, but if you never write a detection for SSTIs, you may miss them entirely.

### Building Lattice Mind and The Scaffolding

The solution is a hybrid approach combining the deterministic, inexpensive scans with structured knowledge and LLM's intelligence to identify vulnerabilites. The first part of this hybrid approach is Lattice Mind.

Lattice Mind is a scanner that the agent can run scans, and can edit the current scan to input its own payload without having to create a script for a whole class of vulnerabilities. Essentially, you grab the low hanging fruits by using deterministic reasoning (i.e. decision trees) to reason about the app architecture, 

For example, if Lattice Mind's scans give the agent enough information to write a payload, it can use Lattice Mind to run a scan with the new payload saving the overhead of it having to write a script to verify/exploit the said SSTI vulnerability.

The Scaffolding is the orchestration layer with skills and MCP servers providing the LLM with access to tools and context needed to perform their security tasks. At the start, the skills looked more like TTPs: what do you detect, where do you go from there, what can you chain etc. Obviously, I had to add a skill improvement skill where the model upon completing a task, evaluates how skills and MCP helped/harmed the run, and then modify the skills to be better next run.

I put it to the test in live CTFs and it was able to solve all the hardest problems consistently in less than 30 minutes. 

## Part II: Technical Notes

### The Benchmark Setup

To me, it seemed obvious that a setup like this would be better than providing the model with no tools and context. My assumption was that these models are trained more for software engineering tasks than security engineering tasks, and TTPs as skills could fill in the gap. I wanted to test my intuition and hence, set up a test bench:  11 models, 3 runs each, control vs skills-only vs MCP-enabled, 20 vulnerability-finding code snippet tasks.

Every model would look at code snippets and try to find vulnerabilites, and I evaluated on two fronts:
- Manual: The largest/most cyber capable model looks through the reasoning and manually grades the answers to check if the reasoning was correct and whether the model suffered from technical issues hindering its solve or whether it named a different CVE, or if it detected a different class of vulnerability in the same snippet. This front was to ensure we're not unfairly assessing models.
- Automated: These vulnerability snippets have certain "correct" answers and we can evaluate by checking how close the models got to the answer.

### The Results Were Not What I Expected

Skills made the weakest models substantially better. On gpt-5.1-codex-mini-low, F1 jumped from 0.4774 to 0.5926, a 24% relative gain, with strict task accuracy climbing 20 percentage points. The rest of the low-baseline group showed the same pattern in the +0.05 to +0.06 F1 range. Across all four models with control F1 below 0.60, skills produced an average ΔF1 of **+0.0656**, dropped FPs per task by 0.08, and lifted strict task accuracy by 10.83 points.

The codex-mini-low lift in particular is the kind of number that changes the math. At $0.25 / $2.00 per million input/output tokens, codex-mini is roughly 12x cheaper on input and 7.5x cheaper on output than Sonnet. Skills pushed its F1 up by nearly a quarter. For agentic security work where running a frontier model on every task is too expensive, scaffolding turns into a real cost lever.

The catch is that the gain is not uniform, and the way it isn't uniform is itself the more interesting finding.

The correlation between baseline F1 and skill uplift across all 11 models is **-0.81**, strong enough that you can predict the sign of the effect from baseline performance alone:

- **Models with control F1 below 0.60** (codex-mini-low, the lower nano variants): average ΔF1 **+0.0656**, FPs per task **down 0.08**, strict accuracy **up 10.83 points**.
- **Models with control F1 at or above 0.75** (mini-high, mini-medium, sonnet-medium): average ΔF1 **-0.0382**, FPs per task **up 0.06**, strict accuracy **down 6.67 points**.

```text
ΔF1 by model (skills - control)

+0.12 | gpt-5.1-codex-mini-low   ████████████
+0.06 | gpt-5.4-nano-none        ██████
+0.05 | gpt-5.4-nano-low         █████
+0.03 | gpt-5.4-nano-high        ███
+0.02 | gpt-5.4-mini-low         ██
+0.02 | gemini-3-flash           ██
-0.02 | kimi-k2.5                ░░
-0.02 | claude-4.6-sonnet-medium ░░
-0.03 | gpt-5.4-mini-high        ░░░
-0.06 | gpt-5.4-nano-medium      ░░░░░░
-0.06 | gpt-5.4-mini-medium      ░░░░░░
```

The mechanism is symmetric on both ends. Weaker models get value out of scaffolding because they were previously omitting findings, getting confused on output structure, or hallucinating shape without substance. 

Skills give them an explicit list of what to look for, what counts as evidence, and the format their answer needs to land in. Recall climbs and FPs drop because there is less room to improvise. 

Stronger models already have all of that internally. Layering structured instructions on top adds no new information, only overhead.

Three model-specific behaviors didn't fit the gradient and are worth pulling out.

**Gemini 3 Flash** improved on single-finding precision (+0.0184 F1, lower FP rate) but its chain-of-exploit success collapsed from 66.7% to 0%. Skills sharpened individual calls and broke multi-step reasoning. If the task requires chaining findings, run Gemini on control. If it requires single-shot precision, skills win.

**Kimi K2.5** regressed objectively (-0.0156 F1) and improved subjectively (+0.0175). Better-sounding reports, worse vulnerability discrimination. Useful as a writeup model, not a triage one.

**Claude Sonnet 4.6** showed the most extreme split. Objective F1 down -0.0178, subjective quality up **+0.2666**, the largest subjective gain anywhere in the run. Skills made Sonnet's reports much clearer and its findings slightly worse.

### MCP didn't beat skills-only. It didn't beat control either.

I expected MCP tools layered on top of skills to push performance higher. Tools should beat instructions. They didn't.

| Profile | Macro F1 | Strict task accuracy |
|---|---:|---:|
| control (3-run mean) | 0.6591 | 50.45% |
| skills-only (3-run mean) | 0.6695 | 51.36% |
| mcp-enabled (single run) | **0.6098** | **46.36%** |

MCP-enabled was below both baselines. Across 11 models, MCP beat control on 3 and beat skills-only on 1. Sonnet took the worst hit at -0.2021 F1 versus control. Codex-mini-low and nano-high also dropped by more than -0.09.

*The MCP run is single-run per model, while the other two profiles are 3-run means, so I cannot claim variance equivalence. But the gap is large enough and consistent enough across 11 models that single-run noise is unlikely to be the whole story.*

The more likely explanation is that the benchmark itself is the wrong test surface, which is what I want to talk about next.

### The Wrong Test Surface

The benchmark told a clear story. MCP made things worse. That story is true on this benchmark, and the benchmark is the wrong instrument for the question I actually care about.

These tasks are static code snippets. The agent receives a code fragment and is asked to name the vulnerability class. 

**There is nothing to run.** 

No service responding to requests, no binary to disassemble, no repository to walk, no browser to drive. The set of things the agent can actually do with a tool is empty. Loading MCP into that context is pure overhead. 

Tool definitions for kali-mcp-server, lattice-mind, ghidra-mcp, and github-mcp consume tokens, advertise capabilities the task cannot use, and invite the model to spend reasoning on tool selection that has no payoff.

The pattern in the data fits that read. The models that lost the most with MCP enabled are also the models most likely to attempt tool calls when they shouldn't have: Sonnet at -0.2021 F1, codex-mini-low at -0.0928, nano-high at -0.1012. 

The stronger the model's bias toward action, the larger the wrong-environment penalty.This does not match what I see on live targets. On running CTF challenges, the same MCP setup is the reason the agent solves problems. On a web challenge it reaches for playwright to walk the app. 

Lattice-mind scans happen nearly every run, firing payloads against a live endpoint. The tools provide signal that does not exist in the prompt.

### How I Changed My Workflow

The biggest change: I stopped running the same scaffold against every model. The harness now routes by what the model is good at and what the stage of the workflow actually needs.

Two rules sit on top of everything else.

Strong models get less. If a model lands above 0.75 control F1, the harness defaults to skills-lite or pure control. Heavy scaffolding cost the high-baseline group an average of 0.04 F1 and pushed FP per task up by 0.06. The skill text was solving a problem these models didn't have.

Weak models get more. If a model lands below 0.60 control F1, the harness defaults to full skills. Skills bought codex-mini-low +0.115 F1 and the nano tier between +0.05 and +0.06. Recall climbs, FPs drop, and output structure stops being a coin flip.

That handles the model-strength axis. The pipeline-stage axis is where most of the practical wins came from.

**Recon goes to cheap models with skills.** Nano-low costs roughly $0.40 per million output tokens, which is five times cheaper than mini and almost forty times cheaper than Sonnet. With skills enabled it gets a +0.05 F1 lift and reduces FPs. For broad surface sweeps where the cost of running it is the constraint and the cost of missing things is recoverable downstream, this is the right slot. I run it wide and rely on a verifier pass later to catch the FPs it produces.

**High-confidence exploit reasoning goes to strong models on control.** Mini-high in control posted the best raw objective F1 in the benchmark at 0.8384. It is also the worst place to layer skills, because the high-baseline regression hits hardest there. Once the harness has narrowed to a small set of candidate findings and needs the highest-discrimination call on each one, mini-high without scaffolding is the cleanest answer in the data.

**Final reports go to Sonnet with skills.** This is the only place where Sonnet's benchmark profile is unambiguously useful. Objective F1 dropped 0.0178 with skills enabled, but subjective quality climbed +0.2666, the largest subjective gain anywhere in the run. Sonnet earns its keep on writing. It costs you on triage. The F1 number reflects both, and the routing should reflect both.

A few smaller calls follow from the same data:

- Gemini Flash on chain-heavy tasks runs control, not skills. Skills broke its chain success from 66.7% down to 0%, and the harness can't afford that drop on multi-step exploitation.
- Kimi K2.5 stays out of triage. It improves narrative quality and degrades discrimination, which is the wrong tradeoff for any stage where a finding is being decided.
- Anything an MCP-equipped agent flags on a static input gets re-run on control before being treated as real. The wrong-environment penalty is large enough that I don't trust those calls in tool-irrelevant contexts.

The harness is no longer one pipeline. It's a router with model-conditional defaults, stage-conditional overrides, and a fallback path for the cases where one of those calls turns out wrong on a specific task. Most of the gain came from the routing, not from any individual scaffolding improvement.

## Practical Tips for Getting More Out of Models

If you build agentic security tooling and you don't want to repeat the trial-and-error path I just walked, here's what shook out as the most useful operational rules.

**1. Stop giving every model the same scaffold.** This is the most consequential single change. Skills helped six of eleven models in this benchmark and hurt five of them. Treating scaffolding as a universally good intervention contradicts the data. Make it a routing decision, not a default.

**2. Weaker models want more structure.** Below 0.60 control F1, the average lift from skills was +0.0656 with falling FPs. Scaffolding is doing real work for these models: filling in the missing classes to look for, the evidence bar to clear, and the shape the output needs to land in. They want the structure. Give it to them.

**3. Stronger models want less formatting burden.** Above 0.75 control F1, scaffolding becomes overhead. Strong models already have the reasoning patterns the skill text is trying to teach. Layering on more structure costs them tokens that should be spent on discrimination. If you're using a high-baseline model, default to skills-lite or pure control and let the model breathe.

**4. Separate recon, exploit reasoning, and reporting.** These are different jobs and they want different models. Recon wants cheap and broad. Exploit reasoning needs the most discriminating model in the lineup. Reporting cares about narrative more than F1. The model that wins one stage is rarely the model that wins another, and the data is unambiguous on this: mini-high posted the best objective F1 on this benchmark, while Sonnet's subjective quality lift was 15x larger than its objective regression. Run them in series, not as substitutes.

**5. Use deterministic tools for deterministic tasks.** If a known-class vulnerability has a scanner that detects it reliably, run the scanner. Don't burn 30K tokens on the LLM rediscovering what a Semgrep rule could have flagged in milliseconds. Save the LLM for what it's actually good at: the cases where there's no rule to write, where the bug spans several files, or where the input is too unstructured for pattern matching. The hybrid is the whole point. Determinism is cheap, intelligence is expensive, and most workflows want both stacked in the right order.

**6. Make MCP earn its place every time.** Tool overhead is real and measurable. On a benchmark where tools had nothing to do, MCP cost the average model 0.05 F1 and dragged Sonnet down by 0.20. Tool definitions are not free even when they go unused, because they sit in context and bias the model toward action. Before plugging an MCP server into an agent, ask whether the task it'll be running on actually contains state for the tool to interrogate. If the answer is no, the tool is buying you nothing and probably costing you something.

**7. Benchmark on the surface you actually deploy on.** This is the lesson I learned the hardest way. Static-snippet benchmarks measure code-level reasoning. They cannot measure whether a tool-equipped agent can hack a live target, even though the temptation to read them that way is enormous. If your system runs against live infrastructure, your benchmark needs to contain live infrastructure. If it reasons about static code, snippets are fine. Pick the surface that matches your real workload, and treat any benchmark that doesn't as a partial signal at best.

None of these are individually surprising. The interesting thing is that they were all sitting in the data once I stopped looking at the macro F1 number and started splitting by baseline strength, stage role, and tool environment.

The natural next test is a real target with real stakes. I've been pointing this setup at open source web infrastructure: CMSes, web servers, proxies, etc and looking for zero-days. A few findings are far enough along that responsible disclosure is in progress. That's what the next post is about.