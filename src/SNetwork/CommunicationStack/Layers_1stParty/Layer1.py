from __future__ import annotations

from dataclasses import dataclass
from ipaddress import IPv6Address
from threading import Thread
from typing import TYPE_CHECKING

from SNetwork.CommunicationStack.Layers_1stParty.LayerN import LayerN, Connection, RawRequest, EncryptedRequest
from SNetwork.CommunicationStack.Layers_2ndParty.Layer1_Abstract import Layer1_Abstract
from SNetwork.Utils.Logger import isolated_logger, LoggerHandlers
from SNetwork.Utils.Socket import Socket
from SNetwork.Utils.Types import Int, List, Type, Optional

if TYPE_CHECKING:
    from SNetwork.CommunicationStack.CommunicationStack import CommunicationStack
    from SNetwork.Managers.KeyManager import KeyStoreData


class Layer1(LayerN):
    _layer_applications: List[Layer1_Abstract]

    @dataclass(kw_only=True)
    class ApplicationLayerRequest(RawRequest):
        application_type: Type[Layer1_Abstract]
        request: RawRequest

    @dataclass(kw_only=True)
    class ApplicationLayerResponse(RawRequest):
        application_type: Type[Layer1_Abstract]
        response: RawRequest

    def __init__(self, stack: CommunicationStack, node_info: KeyStoreData, socket: Socket) -> None:
        super().__init__(stack, node_info, socket, isolated_logger(LoggerHandlers.LAYER_1))
        self._layer_applications = []
        self._logger.info("Layer 1 Ready")

    def register_application(self, application: Layer1_Abstract) -> None:
        """
        Register an application layer to the communication stack. This allows the application to send and receive data
        through the communication stack.
        """

        self._layer_applications.append(application)
        self._logger.info(f"Registered application: {application.__name__}")

    def tunnel_application_data_forwards(self, application: Type[Layer1_Abstract], req: RawRequest) -> None:
        """
        Send data into the front of the communication stack. This is used to send data from the client;s application
        layer into the communication stack, through the route, and to the destination node.
        """

        self._logger.info(f"Tunneling forwards for application: {application.__name__}")
        wrapped = Layer1.ApplicationLayerRequest(application_type=application, request=req)
        self._stack._layer2._send_tunnel_forwards(wrapped)

    def tunnel_application_data_backwards(self, application: Type[Layer1_Abstract], conn: Connection, req: RawRequest) -> None:
        """
        Send data into the back of the communication stack. This is used to send data from the destination node into the
        communication stack, through the route, and to the client's application layer.
        """

        self._logger.info(f"Tunneling backwards for application: {application.__name__}")
        wrapped = Layer1.ApplicationLayerResponse(application_type=application, response=req)
        self._stack._layer2._send_tunnel_backwards(conn, wrapped)

    def _handle_command(self, peer_ip: IPv6Address, peer_port: Int, req: RawRequest, tun_req: Optional[EncryptedRequest] = None) -> None:
        # Match the command to the appropriate handler.
        match req:

            # Handle an application layer request.
            case Layer1.ApplicationLayerRequest():
                thread = Thread(target=self._handle_application_layer_request, args=(peer_ip, peer_port, req, tun_req))
                thread.start()

            # Handle an application layer response.
            case Layer1.ApplicationLayerResponse():
                thread = Thread(target=self._handle_application_layer_response, args=(peer_ip, peer_port, req, tun_req))
                thread.start()

            # Handle either an invalid command from a connected token.
            case _:
                self._logger.warning(f"Received invalid '{req}' request from '{req.conn_tok}'.")

    def _send(self, conn: Connection, req: RawRequest) -> None:
        raise NotImplementedError("Layer 1 does not send data directly. Use Layer 2 tunneling instead.")

    def _handle_application_layer_request(self, peer_ip: IPv6Address, peer_port: Int, request: Layer1.ApplicationLayerRequest, tun_req: Optional[RawRequest] = None) -> None:
        self._logger.info(f"Received '{request.application_type.__name__}' application layer request.")
        layer = [app for app in self._layer_applications if isinstance(app, request.application_type)][0]
        self._logger.info(f"Determined layer: {type(layer).__name__}")
        layer._handle_command(peer_ip, peer_port, request.request, tun_req)

    def _handle_application_layer_response(self, peer_ip: IPv6Address, peer_port: Int, response: Layer1.ApplicationLayerResponse, tun_req: Optional[RawRequest] = None) -> None:
        self._logger.info(f"Received '{response.application_type.__name__}' application layer response.")
        layer = [app for app in self._layer_applications if isinstance(app, response.application_type)][0]
        layer._handle_command(peer_ip, peer_port, response.response, tun_req)
