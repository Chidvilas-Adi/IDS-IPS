import unittest
from unittest.mock import MagicMock, patch

import psycopg2

from pure_db_socket_bridge import PureDBSocketBridge, process_packet_in_db


class FakeDeadlock(psycopg2.Error):
    @property
    def pgcode(self):
        return "40P01"


class PacketBridgeTests(unittest.TestCase):
    def setUp(self):
        self.packet = (
            "192.0.2.1", "192.0.2.2", 12345, 80, "TCP", "SYN",
            "", b"", 40,
        )
        self.connection = MagicMock()
        self.cursor = self.connection.cursor.return_value.__enter__.return_value

    @patch("pure_db_socket_bridge.time.sleep")
    def test_retries_deadlock_and_commits_packet(self, sleep):
        self.cursor.execute.side_effect = [FakeDeadlock("deadlock"), None]

        result = process_packet_in_db(self.connection, self.packet)

        self.assertTrue(result)
        self.assertEqual(self.cursor.execute.call_count, 2)
        self.connection.rollback.assert_called_once()
        self.connection.commit.assert_called_once()
        sleep.assert_called_once_with(0.1)

    @patch("pure_db_socket_bridge.time.sleep")
    def test_drops_packet_after_three_deadlocks_without_killing_bridge(self, sleep):
        self.cursor.execute.side_effect = FakeDeadlock("deadlock")

        result = process_packet_in_db(self.connection, self.packet)

        self.assertFalse(result)
        self.assertEqual(self.cursor.execute.call_count, 3)
        self.assertEqual(self.connection.rollback.call_count, 3)
        self.connection.commit.assert_not_called()
        self.assertEqual(sleep.call_count, 2)

    def test_udp_port_conflict_is_a_warning_not_an_uncaught_thread_error(self):
        udp_socket = MagicMock()
        udp_socket.__enter__.return_value = udp_socket
        udp_socket.bind.side_effect = OSError(10048, "address already in use")

        with (
            patch("pure_db_socket_bridge.get_db_conn"),
            patch("pure_db_socket_bridge.socket.socket", return_value=udp_socket),
            self.assertLogs("DBSocketBridge", level="WARNING") as logs,
        ):
            PureDBSocketBridge()._start_udp_listener("127.0.0.1")

        self.assertTrue(any("raw packet capture" in line for line in logs.output))


if __name__ == "__main__":
    unittest.main()
