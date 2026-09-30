"""Exercise the real FD50/base/coordinator lifecycle without HA or Bluetooth.

Only external dependency boundaries are faked. The identity cipher is not an
encryption test: real packet framing, fragmentation, notification parsing,
datapoints, adapter locks, retry tasks, and coordinator callbacks still execute.
"""

# Keep the regression suite runnable with standard-library unittest alone.
# ruff: noqa: PT009, PT027
import asyncio
import importlib.util
import sys
import unittest
from contextlib import contextmanager
from pathlib import Path
from struct import unpack
from types import ModuleType, SimpleNamespace
from unittest.mock import AsyncMock, patch

COMPONENT = Path(__file__).resolve().parents[1] / "custom_components" / "tuya_ble"
PACKAGE = "_lamomo_lifecycle_testpkg"


def _module(name, **attributes):
    module = ModuleType(name)
    module.__dict__.update(attributes)
    return module


def _load(name, path, *, package=False):
    spec = importlib.util.spec_from_file_location(
        name,
        path,
        submodule_search_locations=[str(path.parent)] if package else None,
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class _IdentityCipher:
    MODE_CBC = object()

    @staticmethod
    def new(key, _mode, iv):
        if not isinstance(key, bytes) or len(key) not in (16, 24, 32):
            raise ValueError("Synthetic cipher requires a valid AES key")
        if len(iv) != 16:
            raise ValueError("Synthetic cipher requires a valid AES IV")
        return _IdentityCipher()

    @staticmethod
    def encrypt(data):
        return bytes(data)

    @staticmethod
    def decrypt(data):
        return bytes(data)


class _Timer:
    def __init__(self, delay, callback):
        self.delay = delay
        self.callback = callback
        self.cancelled = False

    def cancel(self):
        self.cancelled = True

    def fire(self):
        if not self.cancelled:
            self.callback(None)


class _CoordinatorBoundary:
    def __class_getitem__(cls, _arguments):
        return cls

    def __init__(self, hass, _logger, _name=None, **_kwargs):
        self.hass = hass
        self.listener_updates = 0
        self.fresh_updates = 0

    def async_update_listeners(self):
        self.listener_updates += 1

    def async_set_updated_data(self, _data):
        self.fresh_updates += 1
        self.async_update_listeners()


@contextmanager
def _actual_integration():
    """Import actual repository modules with isolated external dependency fakes."""
    connection_error = type("SyntheticBleakError", (Exception,), {})
    connector = _module(
        "bleak_retry_connector",
        BLEAK_BACKOFF_TIME=1,
        BLEAK_RETRY_EXCEPTIONS=(connection_error,),
        BleakClientWithServiceCache=object,
        BleakError=connection_error,
        BleakNotFoundError=connection_error,
        establish_connection=AsyncMock(),
    )

    def async_call_later(hass, delay, callback):
        timer = _Timer(delay, callback)
        hass.timers.append(timer)
        return timer.cancel

    registry = _module(
        "homeassistant.helpers.device_registry", CONNECTION_BLUETOOTH="bluetooth"
    )
    stubs = {
        PACKAGE: _module(PACKAGE, __path__=[str(COMPONENT)]),
        "bleak": _module("bleak", __path__=[]),
        "bleak.exc": _module("bleak.exc", BleakDBusError=connection_error),
        "bleak_retry_connector": connector,
        "Crypto": _module("Crypto", __path__=[]),
        "Crypto.Cipher": _module("Crypto.Cipher", AES=_IdentityCipher),
        "tuya_iot": _module(
            "tuya_iot",
            TuyaCloudOpenAPIEndpoint=SimpleNamespace(
                AMERICA="America", EUROPE="Europe", CHINA="China", INDIA="India"
            ),
        ),
        "homeassistant": _module("homeassistant", __path__=[]),
        "homeassistant.const": _module(
            "homeassistant.const", CONF_ADDRESS="address", CONF_DEVICE_ID="device_id"
        ),
        "homeassistant.core": _module(
            "homeassistant.core",
            CALLBACK_TYPE=object,
            HomeAssistant=object,
            callback=lambda function: function,
        ),
        "homeassistant.helpers": _module(
            "homeassistant.helpers", __path__=[], device_registry=registry
        ),
        "homeassistant.helpers.device_registry": registry,
        "homeassistant.helpers.entity": _module(
            "homeassistant.helpers.entity", DeviceInfo=dict, EntityDescription=object
        ),
        "homeassistant.helpers.event": _module(
            "homeassistant.helpers.event", async_call_later=async_call_later
        ),
        "homeassistant.helpers.update_coordinator": _module(
            "homeassistant.helpers.update_coordinator",
            CoordinatorEntity=object,
            DataUpdateCoordinator=_CoordinatorBoundary,
        ),
    }
    with patch.dict(sys.modules, stubs):
        _load(PACKAGE + ".const", COMPONENT / "const.py")
        transport = _load(
            PACKAGE + ".tuya_ble", COMPONENT / "tuya_ble" / "__init__.py", package=True
        )
        devices = _load(PACKAGE + ".devices", COMPONENT / "devices.py")
        adapter = _load(PACKAGE + ".lamomo_fd50", COMPONENT / "lamomo_fd50.py")
        with patch.object(adapter, "RECONNECT_DELAY", 0.01, create=True):
            yield SimpleNamespace(
                adapter=adapter,
                devices=devices,
                transport=transport,
                code=sys.modules[PACKAGE + ".tuya_ble.const"].TuyaBLECode,
                establish=connector.establish_connection,
            )


class _Manager:
    async def get_device_credentials(self, *_args):
        return SimpleNamespace(
            uuid="synthetic_uuid_01",
            local_key="synthetic_key_01",
            device_id="synthetic_device_id",
            category="dd",
            product_id="0qgrjxum",
            device_name="Synthetic strip",
            product_model=None,
            product_name=None,
            functions=[],
            status_range=[],
        )


class _Client:
    """Synthetic BLE peripheral accepting and producing actual framed packets."""

    def __init__(self, context, device, *, report_status=True):
        self.context = context
        self.device = device
        self.is_connected = True
        self.report_status = report_status
        self.drop_on_control = False
        self.status_requests = 0
        self.buffer = bytearray()
        self.expected_length = 0
        self.notification_sequence = 100
        self.notify = device._notification_handler
        self.values = {
            1: (1, b"\x00"),
            2: (4, b"\x00"),
            5: (3, b"000003e803e8"),
        }

    async def start_notify(self, _uuid, callback, **_kwargs):
        self.notify = callback

    async def disconnect(self):
        self.drop()

    def drop(self):
        self.is_connected = False
        self.device._disconnected(self)

    def _notify(self, code, data, response_to=0):
        self.notification_sequence += 1
        for packet in self.device._build_packets(
            self.notification_sequence, code, data, response_to
        ):
            self.notify(0, packet)

    def report(self):
        for dp_id, (dtype, raw) in self.values.items():
            data = (
                bytes(4)
                + bytes([1, 128, 0, dp_id, dtype])
                + len(raw).to_bytes(2, "big")
                + raw
            )
            self._notify(self.context.code.FUN_RECEIVE_DP_V4, data)

    async def write_gatt_char(self, _uuid, packet, **_kwargs):
        packet_num, position = self.device._unpack_int(packet, 0)
        if packet_num == 0:
            self.buffer.clear()
            self.expected_length, position = self.device._unpack_int(packet, position)
            position += 1
        self.buffer.extend(packet[position:])
        if len(self.buffer) != self.expected_length:
            return
        # Encryption is an identity external boundary, but framing remains real.
        raw = self.buffer[17:]
        sequence, _response_to, code_value, length = unpack(">IIHH", raw[:12])
        code = self.context.code(code_value)
        data = raw[12 : 12 + length]
        if code == self.context.code.FUN_SENDER_DEVICE_INFO:
            info = bytearray(46)
            info[:6] = bytes([1, 1, 4, 4, 0, 1])
            info[6:12] = b"abcdef"
            self._notify(code, bytes(info), sequence)
        elif code == self.context.code.FUN_SENDER_PAIR:
            self._notify(code, b"\x00", sequence)
        elif code == self.context.code.FUN_SENDER_DPS_V4:
            if self.drop_on_control:
                self.drop()
                return
            self.values[data[5]] = (data[6], bytes(data[9:]))
            self._notify(code, bytes(4) + bytes([data[4], 0]), sequence)
        elif code == self.context.code.FUN_SENDER_DEVICE_STATUS:
            self.status_requests += 1
            self._notify(code, b"\x00", sequence)
            if self.report_status:
                self.report()


class LifecycleTests(unittest.IsolatedAsyncioTestCase):
    async def device(self, context):
        device = context.adapter.LamomoFD50Device(
            _Manager(), SimpleNamespace(address="02:00:00:00:00:01")
        )
        await device.initialize()
        hass = SimpleNamespace(timers=[])
        coordinator = context.devices.TuyaBLECoordinator(hass, device)
        return device, coordinator, hass

    async def connected(self, context):
        device, coordinator, hass = await self.device(context)
        client = _Client(context, device)
        context.establish.return_value = client
        await device.update()
        return device, coordinator, hass, client

    async def settle(self):
        for _ in range(8):
            await asyncio.sleep(0)

    async def eventually(self, predicate):
        async with asyncio.timeout(1):
            # Observe synthetic state within a hard test deadline, not production work.
            while not predicate():  # noqa: ASYNC110
                await asyncio.sleep(0.001)

    async def cleanup(self, device):
        device._expected_disconnect = True
        tasks = list(device._background_tasks)
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)

    async def test_startup_failure_has_retry_owner_and_recovers(self):
        with _actual_integration() as context:
            device, coordinator, _hass = await self.device(context)
            client = _Client(context, device)
            context.establish.side_effect = [
                ConnectionError("Temporary radio loss"),
                client,
            ]
            try:
                with self.assertRaises(ConnectionError):
                    await device.update()
                self.assertIsNotNone(device._reconnect_task)
                device.set_ble_device_and_advertisement_data(
                    SimpleNamespace(address=device.address), SimpleNamespace()
                )
                await self.eventually(
                    lambda: device._is_paired and coordinator.connected
                )
                self.assertGreaterEqual(context.establish.await_count, 2)
            finally:
                await self.cleanup(device)

    async def test_start_owns_initial_retry_loop(self):
        with _actual_integration() as context:
            device, coordinator, _hass = await self.device(context)
            client = _Client(context, device)
            context.establish.side_effect = [
                ConnectionError("Temporary radio loss"),
                client,
            ]
            try:
                await device.start()
                self.assertIsNotNone(device._reconnect_task)
                self.assertIn(device._reconnect_task, device._background_tasks)
                await self.eventually(
                    lambda: device._is_paired and coordinator.connected
                )
                self.assertGreaterEqual(context.establish.await_count, 2)
            finally:
                await self.cleanup(device)

    async def test_cached_rollback_preserves_disconnect_timer(self):
        with _actual_integration() as context:
            device, coordinator, hass, client = await self.connected(context)
            client.drop_on_control = True
            context.establish.side_effect = ConnectionError("Device is out of range")
            listeners_before = coordinator.listener_updates
            fresh_before = coordinator.fresh_updates
            try:
                with self.assertRaises(ConnectionError):
                    await device.datapoints[1].set_value(True)
                self.assertIsNone(device._client)
                self.assertFalse(device.datapoints[1].value)
                self.assertGreater(coordinator.listener_updates, listeners_before)
                self.assertEqual(coordinator.fresh_updates, fresh_before)
                self.assertEqual(len(hass.timers), 1)
                self.assertFalse(hass.timers[0].cancelled)
                hass.timers[0].fire()
                self.assertFalse(coordinator.connected)
            finally:
                await self.cleanup(device)

    async def test_connect_failure_rolls_back_without_reviving_unavailable_entity(self):
        with _actual_integration() as context:
            device, coordinator, hass, client = await self.connected(context)
            client.drop()
            hass.timers[-1].fire()
            context.establish.side_effect = ConnectionError("Device is out of range")
            listeners_before = coordinator.listener_updates
            fresh_before = coordinator.fresh_updates
            try:
                with self.assertRaises(ConnectionError):
                    await device.datapoints[1].set_value(True)
                self.assertFalse(device.datapoints[1].value)
                self.assertFalse(coordinator.connected)
                self.assertGreater(coordinator.listener_updates, listeners_before)
                self.assertEqual(coordinator.fresh_updates, fresh_before)
            finally:
                await self.cleanup(device)

    async def test_final_reports_then_disconnect_do_not_lose_active_retry(self):
        with _actual_integration() as context:
            device, _coordinator, _hass, original = await self.connected(context)
            first_retry = _Client(context, device, report_status=False)
            recovered = _Client(context, device)
            context.establish.side_effect = [first_retry, recovered]
            original.drop()
            try:
                await self.eventually(lambda: first_retry.status_requests == 1)
                await self.settle()
                self.assertFalse(device._reconnect_task.done())
                # Both BLE callbacks arrive before the report waiter resumes.
                first_retry.report()
                first_retry.drop()
                await self.eventually(
                    lambda: device._client is recovered and device._is_paired
                )
                self.assertTrue(recovered.is_connected)
            finally:
                await self.cleanup(device)

    async def test_repeated_failures_share_one_retry_task(self):
        with _actual_integration() as context:
            device, _coordinator, _hass = await self.device(context)
            context.establish.side_effect = ConnectionError("Device is out of range")
            try:
                with self.assertRaises(ConnectionError):
                    await device.update()
                retry = device._reconnect_task
                self.assertIsNotNone(retry)
                for _ in range(2):
                    with self.assertRaises(ConnectionError):
                        await device.update()
                    self.assertIs(device._reconnect_task, retry)
                self.assertEqual(device._background_tasks, {retry})
            finally:
                await self.cleanup(device)

    async def test_stop_cancels_retry_and_prevents_new_attempts(self):
        with _actual_integration() as context:
            device, _coordinator, _hass, client = await self.connected(context)
            context.establish.side_effect = ConnectionError("Device is out of range")
            client.drop()
            try:
                await self.eventually(lambda: context.establish.await_count >= 2)
                retry = device._reconnect_task
                await device.stop()
                await self.settle()
                self.assertTrue(retry.done())
                self.assertFalse(device._background_tasks)
                calls_at_stop = context.establish.await_count
                with self.assertRaises(ConnectionError):
                    await device.update()
                await asyncio.sleep(0.02)
                self.assertEqual(context.establish.await_count, calls_at_stop)
                self.assertIsNone(device._client)
            finally:
                await self.cleanup(device)

    async def test_stop_promptly_cancels_in_flight_retry_connection(self):
        with _actual_integration() as context:
            device, _coordinator, _hass, client = await self.connected(context)
            entered = asyncio.Event()

            async def blocked_connection(*_args, **_kwargs):
                entered.set()
                await asyncio.Event().wait()

            context.establish.side_effect = blocked_connection
            client.drop()
            try:
                await asyncio.wait_for(entered.wait(), 1)
                retry = device._reconnect_task
                await asyncio.wait_for(device.stop(), 0.3)
                self.assertTrue(retry.done())
                self.assertTrue(all(task.done() for task in device._background_tasks))
                await self.settle()
                self.assertFalse(device._background_tasks)
                self.assertIsNone(device._client)
                self.assertFalse(device._connect_lock.locked())
            finally:
                await self.cleanup(device)

    async def test_real_reconnect_rearms_next_disconnect_timer(self):
        with _actual_integration() as context:
            device, coordinator, hass, client = await self.connected(context)
            next_client = _Client(context, device)
            context.establish.return_value = next_client
            client.drop()
            try:
                await self.eventually(
                    lambda: device._client is next_client and device._is_paired
                )
                await self.settle()
                self.assertTrue(hass.timers[0].cancelled)
                next_client.drop()
                self.assertEqual(len(hass.timers), 2)
                hass.timers[1].fire()
                self.assertFalse(coordinator.connected)
            finally:
                await self.cleanup(device)


if __name__ == "__main__":
    unittest.main()
