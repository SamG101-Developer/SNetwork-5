from SNetwork.CommunicationStack.CommunicationStack import CommunicationStack
from SNetwork.Managers.KeyManager import KeyStoreData


class AbstractNode:
    _stack: CommunicationStack
    _info: KeyStoreData
