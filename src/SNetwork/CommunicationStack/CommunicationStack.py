from SNetwork.CommunicationStack.Layer1 import Layer1
from SNetwork.CommunicationStack.Layer2 import Layer2
from SNetwork.CommunicationStack.Layer3 import Layer3
from SNetwork.CommunicationStack.Layer4 import Layer4


class CommunicationStack:
    """
    The Communication Stack class is used to create the layers of the communication stack. The stack is accessible to
    each layer of the stack, as some-cross layer communication is required.
    """

    _layer1: Layer1
    _layer2: Layer2
    _layer3: Layer3
    _layer4: Layer4

    def __init__(self):
        # Create the layers of the stack.
        self._layer4 = Layer4(self)
        self._layer3 = Layer3(self)
        self._layer2 = Layer2(self)
        self._layer1 = Layer1(self)


__all__ = ["CommunicationStack"]
