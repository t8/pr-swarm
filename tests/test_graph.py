from pr_swarm.graph import build_graph, route_after_diff_parser, SPECIALIST_NODES


class TestRouteAfterDiffParser:
    def test_normal_pr(self):
        state = {"errors": []}
        assert route_after_diff_parser(state) == SPECIALIST_NODES

    def test_oversized_pr(self):
        state = {"errors": [{"agent": "diff_parser", "error": "too big", "escalate": True}]}
        assert route_after_diff_parser(state) == "oversized_handler"

    def test_non_escalating_error(self):
        state = {"errors": [{"agent": "security_auditor", "error": "timeout"}]}
        assert route_after_diff_parser(state) == SPECIALIST_NODES


class TestBuildGraph:
    def test_graph_compiles(self):
        graph = build_graph()
        app = graph.compile()
        assert app is not None
