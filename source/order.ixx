// SPDX-License-Identifier: GPL-3.0-or-later
//
// xla.order — the declarative init plan: a phase per step, named `after` and
// `prerequisites` edges, and a deterministic topological sort with cycle detection.
//
// The original add-on ran a straight-line `Init`; that sequence is data (the
// launcher stage order, the option-to-installer order), so the plan below keeps
// it 1:1 while making each dependency explicit and checkable. `addon.ixx` runs
// the steps in the order this module returns; `xla_tests` pins that order with a
// golden name list and exercises the cycle/missing-edge diagnostics.
//
// Phase model: `probe` establishes that the process is the game and finds the
// paths; `config` reads the INI, applies the FusionFix gates and resolves the
// image and build (all facts the installers consume); `install` performs the
// writes; `post` reports completion. There is no pipeline-level `publish` phase:
// every publish-before-install edge in this add-on lives inside an install step
// (the launcher's CreateFile slot, the intro resume, the menu call target), and
// those steps keep their own capture-before-write order and tests.

module;

#include "common.hxx"

export module xla.order;

import xla.common;

export namespace xla::order
{
    enum class Phase : std::uint8_t
    {
        probe,
        config,
        install,
        post,
    };

    struct Node
    {
        std::string_view name; // unique, stable: the golden order test keys on it
        Phase phase;
        std::span<const std::string_view> after;    // must run after these
        std::span<const std::string_view> prerequisites; // hard prerequisites
    };

    struct Plan
    {
        // Indices into the input node span, in execution order. Empty when the
        // plan is invalid (fail closed: a broken order installs nothing).
        std::vector<std::size_t> order;
        std::vector<std::string> diagnostics;
        bool valid{};
    };

    // Deterministic Kahn sort: the ready set is ordered by (phase, declaration
    // index), so the result never depends on the container or on the caller's
    // registration order. Both edge kinds are ordering edges; `prerequisites` is also
    // checked at run time by the executor (a stopped prerequisite stops the run).
    [[nodiscard]] Plan Build(std::span<const Node> nodes);

    // The add-on's own plan, in declaration order (which is the original's order
    // where no edge decides otherwise).
    [[nodiscard]] constexpr std::span<const Node> Pipeline() noexcept;
} // namespace xla::order

namespace xla::order
{
    namespace
    {
        [[nodiscard]] constexpr std::string_view PhaseName(Phase phase) noexcept
        {
            switch (phase)
            {
            case Phase::probe:
                return "probe";
            case Phase::config:
                return "config";
            case Phase::install:
                return "install";
            case Phase::post:
                return "post";
            }
            return "?";
        }

        [[nodiscard]] std::size_t FindNode(std::span<const Node> nodes,
                                           std::string_view name) noexcept
        {
            for (std::size_t index = 0; index < nodes.size(); ++index)
            {
                if (nodes[index].name == name)
                {
                    return index;
                }
            }
            return nodes.size();
        }

        // Reconstruct one cycle from the nodes Kahn could not emit, so the
        // diagnostic names a path instead of dumping the residual set.
        [[nodiscard]] std::vector<std::size_t> FindCycle(
            std::span<const Node> nodes, std::span<const std::size_t> residual)
        {
            auto in_residual = [&](std::size_t index) {
                return std::find(residual.begin(), residual.end(), index) != residual.end();
            };

            std::vector<std::size_t> path;
            std::vector<std::size_t> state(nodes.size(), 0); // 0 unvisited, 1 in path, 2 done

            // The graph is the `after`/`prerequisites` edge set restricted to residual.
            auto visit = [&](auto&& self, std::size_t index) -> bool {
                state[index] = 1;
                path.push_back(index);
                for (const std::span<const std::string_view> edges :
                     {nodes[index].after, nodes[index].prerequisites})
                {
                    for (const std::string_view name : edges)
                    {
                        const std::size_t next = FindNode(nodes, name);
                        if (next == nodes.size() || !in_residual(next))
                        {
                            continue;
                        }
                        if (state[next] == 1)
                        {
                            const auto start = std::find(path.begin(), path.end(), next);
                            path.erase(path.begin(), start);
                            return true;
                        }
                        if (state[next] == 0 && self(self, next))
                        {
                            return true;
                        }
                    }
                }
                path.pop_back();
                state[index] = 2;
                return false;
            };

            for (const std::size_t index : residual)
            {
                if (state[index] == 0 && visit(visit, index))
                {
                    return path;
                }
            }
            return {};
        }
    } // namespace

    Plan Build(std::span<const Node> nodes)
    {
        Plan plan;
        plan.valid = true;

        // Names are the public identity of a step: duplicates make the golden
        // list and the diagnostics ambiguous.
        for (std::size_t i = 0; i < nodes.size(); ++i)
        {
            for (std::size_t j = i + 1; j < nodes.size(); ++j)
            {
                if (nodes[i].name == nodes[j].name)
                {
                    plan.diagnostics.push_back(std::format("order: duplicate step '{}'",
                                                           nodes[i].name));
                    plan.valid = false;
                }
            }
        }

        std::vector<std::vector<std::size_t>> successors(nodes.size());
        std::vector<std::size_t> indegree(nodes.size(), 0);

        for (std::size_t index = 0; index < nodes.size(); ++index)
        {
            const Node& node = nodes[index];
            for (const std::span<const std::string_view> edges : {node.after, node.prerequisites})
            {
                for (const std::string_view name : edges)
                {
                    const std::size_t target = FindNode(nodes, name);
                    if (target == nodes.size())
                    {
                        plan.diagnostics.push_back(
                            std::format("order: '{}' depends on absent '{}'", node.name, name));
                        plan.valid = false;
                        continue;
                    }
                    if (static_cast<std::uint8_t>(nodes[target].phase) >
                        static_cast<std::uint8_t>(node.phase))
                    {
                        plan.diagnostics.push_back(std::format(
                            "order: phase inversion: '{}' ({}) depends on '{}' ({})", node.name,
                            PhaseName(node.phase), name, PhaseName(nodes[target].phase)));
                        plan.valid = false;
                        continue;
                    }
                    successors[target].push_back(index);
                    ++indegree[index];
                }
            }
        }

        if (!plan.valid)
        {
            return plan;
        }

        std::vector<std::size_t> ready;
        for (std::size_t index = 0; index < nodes.size(); ++index)
        {
            if (indegree[index] == 0)
            {
                ready.push_back(index);
            }
        }

        while (!ready.empty())
        {
            const auto pick = std::min_element(ready.begin(), ready.end(),
                                               [&](std::size_t left, std::size_t right) {
                                                   const auto left_key = std::pair{
                                                       static_cast<std::uint8_t>(
                                                           nodes[left].phase),
                                                       left};
                                                   const auto right_key = std::pair{
                                                       static_cast<std::uint8_t>(
                                                           nodes[right].phase),
                                                       right};
                                                   return left_key < right_key;
                                               });
            const std::size_t index = *pick;
            ready.erase(pick);
            plan.order.push_back(index);

            for (const std::size_t next : successors[index])
            {
                if (--indegree[next] == 0)
                {
                    ready.push_back(next);
                }
            }
        }

        if (plan.order.size() != nodes.size())
        {
            plan.valid = false;
            plan.order.clear();
            std::vector<std::size_t> residual;
            for (std::size_t index = 0; index < nodes.size(); ++index)
            {
                if (indegree[index] != 0)
                {
                    residual.push_back(index);
                }
            }
            const std::vector<std::size_t> cycle = FindCycle(nodes, residual);
            if (!cycle.empty())
            {
                std::string text = "order: cycle";
                for (const std::size_t index : cycle)
                {
                    text += std::format(" {} ->", nodes[index].name);
                }
                text += " ";
                text += nodes[cycle.front()].name;
                plan.diagnostics.push_back(std::move(text));
            }
            else
            {
                plan.diagnostics.push_back(
                    std::format("order: {} step(s) cannot be ordered", residual.size()));
            }
        }
        return plan;
    }

    constexpr std::span<const Node> Pipeline() noexcept
    {
        // The original add-on's sequence, with each dependency that the step
        // actually has. `after` edges are the ones that decide the order; the
        // declaration order is only the tie-break for independent steps.
        using enum Phase;

        static constexpr std::string_view kAfterConsole[]{"banner"};
        static constexpr std::string_view kAfterProbe[]{"console"};
        static constexpr std::string_view kAfterPaths[]{"probe"};
        static constexpr std::string_view kAfterConfig[]{"paths"};
        static constexpr std::string_view kAfterFusionFix[]{"config"};
        static constexpr std::string_view kAfterReportConfig[]{"fusionfix"};
        static constexpr std::string_view kAfterImage[]{"report-config"};
        static constexpr std::string_view kAfterWritable[]{"image"};
        static constexpr std::string_view kAfterBuild[]{"writable"};
        static constexpr std::string_view kAfterLocalSettings[]{"build"};
        static constexpr std::string_view kAfterSavegames[]{"local-settings"};
        static constexpr std::string_view kAfterSkipLauncher[]{"savegames"};
        static constexpr std::string_view kAfterBorderless[]{"skip-launcher"};
        static constexpr std::string_view kAfterFocusLoss[]{"borderless-hooks"};
        static constexpr std::string_view kAfterCorePatches[]{"focus-loss"};
        static constexpr std::string_view kAfterLauncherStage[]{"core-patches"};
        static constexpr std::string_view kAfterWebConnect[]{"launcher-stage"};
        static constexpr std::string_view kAfterIntro[]{"web-connect"};
        static constexpr std::string_view kAfterMenu[]{"intro"};
        static constexpr std::string_view kAfterDoNotPause[]{"menu"};
        static constexpr std::string_view kAfterDefWindow[]{"do-not-pause"};
        static constexpr std::string_view kAfterRegistry[]{"defwindow-shims"};
        static constexpr std::string_view kAfterVram[]{"registry"};
        static constexpr std::string_view kAfterComplete[]{"vram"};

        // Hard prerequisites: the config must be resolved before any step reads
        // an option, the image before it is made writable, and the build before
        // any installer consults it. These are ordering edges too.
        static constexpr std::string_view kPrerequisitesConfig[]{"config"};
        static constexpr std::string_view kPrerequisitesImage[]{"image"};
        static constexpr std::string_view kPrerequisitesWritable[]{"writable"};
        static constexpr std::string_view kPrerequisitesLauncher[]{"build", "writable"};

        static constexpr Node kPipeline[] = {
            {"banner", probe, {}, {}},
            {"console", probe, kAfterConsole, {}},
            {"probe", probe, kAfterProbe, {}},
            {"paths", probe, kAfterPaths, {}},
            {"config", config, kAfterConfig, {}},
            {"fusionfix", config, kAfterFusionFix, {}},
            {"report-config", config, kAfterReportConfig, {}},
            {"image", config, kAfterImage, kPrerequisitesConfig},
            {"writable", config, kAfterWritable, kPrerequisitesImage},
            {"build", config, kAfterBuild, kPrerequisitesWritable},
            {"local-settings", install, kAfterLocalSettings, kPrerequisitesLauncher},
            {"savegames", install, kAfterSavegames, kPrerequisitesConfig},
            {"skip-launcher", install, kAfterSkipLauncher, kPrerequisitesLauncher},
            {"borderless-hooks", install, kAfterBorderless, kPrerequisitesConfig},
            {"focus-loss", install, kAfterFocusLoss, kPrerequisitesConfig},
            {"core-patches", install, kAfterCorePatches, kPrerequisitesLauncher},
            {"launcher-stage", install, kAfterLauncherStage, kPrerequisitesLauncher},
            {"web-connect", install, kAfterWebConnect, kPrerequisitesConfig},
            {"intro", install, kAfterIntro, kPrerequisitesConfig},
            {"menu", install, kAfterMenu, kPrerequisitesConfig},
            {"do-not-pause", install, kAfterDoNotPause, kPrerequisitesConfig},
            {"defwindow-shims", install, kAfterDefWindow, kPrerequisitesConfig},
            {"registry", install, kAfterRegistry, kPrerequisitesWritable},
            {"vram", install, kAfterVram, kPrerequisitesConfig},
            {"complete", post, kAfterComplete, {}},
        };
        return kPipeline;
    }
} // namespace xla::order
