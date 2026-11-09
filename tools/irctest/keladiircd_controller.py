"""irctest controller that starts one KeladiIRCd process per test case."""

import os
import subprocess
from typing import Optional, Set, Tuple, Type

from irctest.basecontrollers import BaseServerController, DirectoryBasedController
from irctest.runner import NotImplementedByController

BINARY = os.environ["KELADIIRCD_BIN"]


class KeladiircdController(BaseServerController, DirectoryBasedController):
    software_name = "KeladiIRCd"
    supported_sasl_mechanisms: Set[str] = set()
    supports_sts = False

    def run(
        self,
        hostname: str,
        port: int,
        *,
        password: Optional[str],
        ssl: bool,
        run_services: bool,
        faketime: Optional[str],
        websocket_hostname: Optional[str],
        websocket_port: Optional[int],
    ) -> None:
        if ssl:
            raise NotImplementedByController("TLS")
        if websocket_hostname is not None or websocket_port is not None:
            raise NotImplementedByController("Websocket")
        if run_services:
            raise NotImplementedByController("Services")
        assert self.proc is None
        self.port = port
        self.hostname = hostname
        self.create_config()
        assert self.directory
        with self.open_file("keladiircd.conf") as fd:
            # irctest's standard operator credentials.
            fd.write("oper operuser * override IRCTEST_OPER_PASSWORD\n")
        env = dict(os.environ, IRCTEST_OPER_PASSWORD="operpassword")
        env.pop("KELADIIRCD_PASSWORD", None)
        if password:
            env["KELADIIRCD_PASSWORD"] = password
        self.proc = self.execute(
            [
                BINARY,
                "--listen",
                f"{hostname}:{port}",
                "--name",
                "My.Little.Server",
                # Other irctest controllers configure this same description.
                "--description",
                "test server",
                "--config",
                self.directory / "keladiircd.conf",
            ],
            env=env,
        )

    def get_hostname_and_port(self) -> Tuple[str, int]:
        # irctest picks 0.0.0.0, which Windows cannot connect to.
        (_, port) = super().get_hostname_and_port()
        return ("127.0.0.1", port)

    def kill_proc(self) -> None:
        # The base class uses os.killpg, which does not exist on Windows.
        assert self.proc
        self.proc.terminate()
        try:
            self.proc.wait(5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait(10)
        self.proc = None


def get_irctest_controller_class() -> Type[KeladiircdController]:
    return KeladiircdController
