# Testbed Topology Figures

File `docs/TESTBED_TOPOLOGY.md` was not present in the repository, so this
document records the generated figure sources for the current PAD-ONAP
testbed topology.

## TikZ for LaTeX

The TikZ source files are in `docs/figs/`:

- `testbed_remote_pipeline.tikz`: local Mininet to remote K8s + ONAP flow.
- `testbed_3slice_topology.tikz`: PAD-ONAP 3-slice Mininet topology from
  `testbed/mininet/topology.py`.
- `testbed_fat_tree_k4_topology.tikz`: fat-tree `k=4` topology from
  `testbed/mininet/fat_tree_topology.py`.
- `testbed_topologies_tikz_examples.tex`: ready-to-copy LaTeX figure wrappers.

Example usage in `docs/main.tex`:

```latex
\begin{figure}[H]
\centering
\resizebox{\textwidth}{!}{\input{figs/testbed_remote_pipeline.tikz}}
\caption{Remote-pipeline testbed topology.}
\label{fig:testbed-remote-pipeline}
\end{figure}
```

The thesis preamble already loads TikZ and the required libraries:
`calc`, `positioning`, `shapes.geometric`, `fit`, and `arrows.meta`.

## draw.io

Open this file with diagrams.net / draw.io:

- `docs/figs/testbed_topologies.drawio`

It contains three pages matching the TikZ figures:

- `Remote Pipeline`
- `3-Slice Mininet`
- `Fat-Tree k=4`

## Source Mapping

- Remote pipeline: derived from `docs/REMOTE_TESTBED_RUNBOOK.md`.
- 3-slice topology: derived from `testbed/mininet/topology.py`.
- Fat-tree topology: derived from `testbed/mininet/fat_tree_topology.py`.
