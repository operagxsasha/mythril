import unittest.mock as mock
from unittest.mock import MagicMock

from mythril.laser.ethereum.state.account import Account
from mythril.laser.ethereum.state.world_state import WorldState
from mythril.laser.ethereum.svm import LaserEVM
from mythril.laser.ethereum.transaction import (
    ContractCreationTransaction,
    MessageCallTransaction,
)
from mythril.laser.ethereum.transaction.symbolic import (
    execute_contract_creation,
    execute_message_call,
)
from mythril.laser.smt import symbol_factory


def _is_message_call(_, transaction, transaction_sequences):
    assert isinstance(transaction, MessageCallTransaction)


def _is_contract_creation(_, transaction):
    assert isinstance(transaction, ContractCreationTransaction)


@mock.patch(
    "mythril.laser.ethereum.transaction.symbolic._setup_global_state_for_execution"
)
def test_execute_message_call(mocked_setup: MagicMock):
    # Arrange
    laser_evm = LaserEVM({})

    world_state = WorldState()
    world_state.put_account(Account("0x0"))

    laser_evm.open_states = [world_state]
    laser_evm.exec = MagicMock()

    mocked_setup.side_effect = _is_message_call

    # Act
    execute_message_call(laser_evm, symbol_factory.BitVecVal(0, 256))

    # Assert
    # laser_evm.exec.assert_called_once()
    assert laser_evm.exec.call_count == 1
    # mocked_setup.assert_called_once()
    assert mocked_setup.call_count == 1

    assert len(laser_evm.open_states) == 0


@mock.patch(
    "mythril.laser.ethereum.transaction.symbolic._setup_global_state_for_execution"
)
def test_execute_contract_creation(mocked_setup: MagicMock):
    # Arrange
    laser_evm = LaserEVM({})

    laser_evm.open_states = [WorldState(), WorldState()]
    laser_evm.exec = MagicMock()
    mocked_setup.side_effect = _is_contract_creation

    # Act
    execute_contract_creation(laser_evm, "606000")

    # Assert
    # mocked_setup.assert_called()
    assert mocked_setup.call_count >= 1
    # laser_evm.exec.assert_called_once()
    assert laser_evm.exec.call_count == 1
    assert len(laser_evm.open_states) == 0
