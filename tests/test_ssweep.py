import os, sys, unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import ssweep as s


class Parsing(unittest.TestCase):
    def test_ipv4(self):
        self.assertEqual(s.parse_addr("0100007F", 0), "127.0.0.1")
        self.assertEqual(s.parse_addr("00000000", 0), "0.0.0.0")

    def test_ipv6(self):
        self.assertEqual(s.parse_addr("00000000000000000000000001000000", 1), "::1")
        self.assertEqual(s.parse_addr("0" * 32, 1), "::")

    def test_cgroup_unit(self):
        self.assertEqual(s.unit_from_cgroup("0::/system.slice/apache2.service\n"), "apache2.service")
        self.assertIsNone(s.unit_from_cgroup("0::/user.slice/user-1000.slice/user@1000.service/app.slice/x.scope"))
        self.assertIsNone(s.unit_from_cgroup("0::/user.slice/session-2.scope"))

    def test_fmt_ports(self):
        raw = "0.0.0.0:8080->80/tcp, :::8080->80/tcp, 127.0.0.1:5432->5432/tcp, 3306/tcp"
        self.assertEqual(s.fmt_ports(raw), "8080->80, 5432->5432 (local)")
        self.assertEqual(s.fmt_ports(""), "-")

    def test_published_ranges(self):
        c = {"state": "running", "ports": "0.0.0.0:8000-8001->9000-9001/tcp", "name": "x", "id": "i"}
        m = s.published([c])
        self.assertEqual(m[("tcp", 8001)][1], 9001)
        self.assertEqual(s.published([dict(c, state="exited")]), {})

    def test_bind_label(self):
        self.assertEqual(s.bind_label(["0.0.0.0"])[0], "ALL")
        self.assertEqual(s.bind_label(["127.0.0.1", "::1"])[0], "local")
        self.assertEqual(s.bind_label(["10.0.0.5"])[0], "10.0.0.5")


class Selection(unittest.TestCase):
    def test_ok(self):
        self.assertEqual(s.parse_selection("1 3 5-6 s2", 8),
                         [(1, "rm"), (3, "rm"), (5, "rm"), (6, "rm"), (2, "stop")])

    def test_errors(self):
        for bad in ("0", "9", "x", "3-1"):
            with self.assertRaises(ValueError):
                s.parse_selection(bad, 8)


class DockerLogic(unittest.TestCase):
    IMGS = [
        {"ID": "sha256:a", "Repository": "nginx", "Tag": "latest", "Size": "1MB", "CreatedSince": "x"},
        {"ID": "sha256:b", "Repository": "kali", "Tag": "latest", "Size": "1MB", "CreatedSince": "x"},
        {"ID": "sha256:c", "Repository": "<none>", "Tag": "<none>", "Size": "1MB", "CreatedSince": "x"},
    ]

    def states(self, containers, inspect):
        with mock.patch.object(s, "docker_json", return_value=self.IMGS), \
             mock.patch.object(s, "docker_lines", return_value=inspect):
            return {i["name"]: i["state"] for i in s.get_images(containers)}

    def test_unused_and_dangling(self):
        got = self.states([{"id": "1"}], ["sha256:a"])
        self.assertEqual(got, {"nginx:latest": "in use", "kali:latest": "unused", "<none>": "dangling"})

    def test_unknown_usage_is_never_unused(self):  # inspect failed -> be safe
        got = self.states([{"id": "1"}], None)
        self.assertNotIn("unused", got.values())


class Actions(unittest.TestCase):
    def test_container_commands(self):
        calls = []
        with mock.patch.object(s, "run", side_effect=lambda c, t=0: (calls.append(c), (0, "", ""))[1]):
            s.perform({"kind": "container", "id": "abc", "state": "running"}, "stop")
            s.perform({"kind": "container", "id": "abc", "state": "running"}, "rm")
            s.perform({"kind": "image", "ref": "nginx:latest"}, "rm")
        self.assertEqual(calls, [["docker", "stop", "abc"], ["docker", "rm", "-f", "abc"], ["docker", "rmi", "nginx:latest"]])

    def test_stop_already_stopped(self):
        ok, msg = s.perform({"kind": "container", "id": "abc", "state": "exited"}, "stop")
        self.assertTrue(ok)

    def test_image_cannot_be_stopped(self):
        self.assertFalse(s.perform({"kind": "image", "ref": "x"}, "stop")[0])


class Live(unittest.TestCase):
    def test_collect_runs_without_docker(self):
        with mock.patch.object(s, "run", return_value=(127, "", "docker: not found")):
            d = s.collect()
        self.assertIsNone(d["containers"])
        self.assertEqual(d["docker_error"], "docker is not installed")
        self.assertIsInstance(d["ports"], list)


if __name__ == "__main__":
    unittest.main()
