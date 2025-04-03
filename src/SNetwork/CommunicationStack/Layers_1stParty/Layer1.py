from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from ipaddress import IPv6Address
from threading import Thread
from typing import TYPE_CHECKING

from SNetwork.CommunicationStack.Layers_1stParty.LayerN import LayerN, Connection, LayerNProtocol, RawRequest
from SNetwork.CommunicationStack.Layers_2ndParty.Layer1_Abstract import Layer1_Abstract
from SNetwork.Utils.Logger import isolated_logger, LoggerHandlers
from SNetwork.Utils.Socket import Socket
from SNetwork.Utils.Types import Int, List, Type

if TYPE_CHECKING:
    from SNetwork.CommunicationStack.CommunicationStack import CommunicationStack
    from SNetwork.Managers.KeyManager import KeyStoreData


class Layer1Protocol(LayerNProtocol, Enum):
    pass


class Layer1(LayerN):
    _layer_applications: List[Layer1_Abstract]

    @dataclass(kw_only=True)
    class ApplicationLayerRequest(RawRequest):
        application: Type[Layer1_Abstract]
        request: RawRequest

    @dataclass(kw_only=True)
    class ApplicationLayerResponse(RawRequest):
        application: Type[Layer1_Abstract]
        response: RawRequest

    def __init__(self, stack: CommunicationStack, node_info: KeyStoreData, socket: Socket) -> None:
        super().__init__(stack, node_info, Layer1Protocol, socket, isolated_logger(LoggerHandlers.LAYER_1))
        self._layer_applications = []
        self._logger.info("Layer 1 Ready")

    def register_application(self, application: Layer1_Abstract) -> None:
        """
        Register an application layer to the communication stack. This allows the application to send and receive data
        through the communication stack.
        """

        self._layer_applications.append(application)
        self._logger.info(f"Registered application: {application.__class__.__name__}")

    def tunnel_application_data_forwards(self, application: Type[Layer1_Abstract], req: RawRequest) -> None:
        """
        Send data into the front of the communication stack. This is used to send data from the client;s application
        layer into the communication stack, through the route, and to the destination node.
        """

        wrapped = Layer1.ApplicationLayerRequest(application=application, request=req)
        self._stack._layer2._send_tunnel_forwards(wrapped)

    def tunnel_application_data_backwards(self, application: Type[Layer1_Abstract], conn: Connection, req: RawRequest) -> None:
        """
        Send data into the back of the communication stack. This is used to send data from the destination node into the
        communication stack, through the route, and to the client's application layer.
        """

        wrapped = Layer1.ApplicationLayerResponse(application=application, response=req)
        self._stack._layer2._send_tunnel_backwards(conn, wrapped)

    def _handle_command(self, peer_ip: IPv6Address, peer_port: Int, req: RawRequest) -> None:
        # Match the command to the appropriate handler.
        match req:

            # Handle an application layer request.
            case Layer1.ApplicationLayerRequest:
                thread = Thread(target=self._handle_application_layer_request, args=(peer_ip, peer_port, req))
                thread.start()

            # Handle an application layer response.
            case Layer1.ApplicationLayerResponse:
                thread = Thread(target=self._handle_application_layer_response, args=(peer_ip, peer_port, req))
                thread.start()

    def _send(self, conn: Connection, req: RawRequest) -> None:
        raise NotImplementedError("Layer 1 does not send data directly. Use Layer 2 tunneling instead.")

    def _handle_application_layer_request(self, peer_ip: IPv6Address, peer_port: Int, request: Layer1.ApplicationLayerRequest) -> None:
        layer = [app for app in self._layer_applications if type(app) is request.application][0]
        layer._handle_command(peer_ip, peer_port, request.request)

    def _handle_application_layer_response(self, peer_ip: IPv6Address, peer_port: Int, response: Layer1.ApplicationLayerResponse) -> None:
        layer = [app for app in self._layer_applications if type(app) is response.application][0]
        layer._handle_command(peer_ip, peer_port, response.response)
