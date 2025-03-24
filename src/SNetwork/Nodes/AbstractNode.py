from SNetwork.CommunicationStack.CommunicationStack import CommunicationStack
from SNetwork.CommunicationStack.Layers_1stParty.LayerD import LayerD
from SNetwork.Managers.KeyManager import KeyStoreData


class AbstractNode:
    _stack: CommunicationStack
    _info: KeyStoreData
    _boot: LayerD
