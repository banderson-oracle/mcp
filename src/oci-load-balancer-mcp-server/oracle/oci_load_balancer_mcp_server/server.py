"""
Copyright (c) 2025, Oracle and/or its affiliates.
Licensed under the Universal Permissive License v1.0 as shown at
https://oss.oracle.com/licenses/upl.
"""

import os
from logging import Logger
from typing import Literal, Optional

import oci
from fastmcp import FastMCP
from oracle.oci_load_balancer_mcp_server.models import (
    Backend,
    BackendSet,
    Listener,
    LoadBalancer,
    Response,
    map_backend_set,
    map_listener,
    map_load_balancer,
    map_response,
)
from pydantic import Field

from . import __project__, __version__

logger = Logger(__name__, level="INFO")

mcp = FastMCP(
    name=__project__,
    instructions="This server provides tools to interact with the OCI Load Balancer resources. It includes tools to help with managing load balancers.",
)


def get_load_balancer_client():
    logger.info("entering get_load_balancer_client")
    config = oci.config.from_file(
        profile_name=os.getenv("OCI_CONFIG_PROFILE", oci.config.DEFAULT_PROFILE)
    )
    user_agent_name = __project__.split("oracle.", 1)[1].split("-server", 1)[0]
    config["additional_user_agent"] = f"{user_agent_name}/{__version__}"
    private_key = oci.signer.load_private_key_from_file(config["key_file"])
    # Use the same token-based signer approach used in other servers for consistency
    token_file = (
        os.path.expanduser(config["security_token_file"])
        if "security_token_file" in config
        else None
    )
    token = None
    if token_file:
        with open(token_file, "r") as f:
            token = f.read()
    signer = oci.auth.signers.SecurityTokenSigner(token, private_key) if token else None
    return oci.load_balancer.LoadBalancerClient(config, signer=signer)


@mcp.tool(
    name="list_load_balancers",
    description="Lists the load balancers from the given compartment",
)
def list_load_balancers(
    compartment_id: str = Field(..., description="The OCID of the compartment"),
    limit: Optional[int] = Field(
        None,
        description="The maximum amount of load balancers to return. If None, there is no limit.",
        ge=1,
    ),
    lifecycle_state: Optional[
        Literal[
            "CREATING",
            "FAILED",
            "ACTIVE",
            "DELETING",
            "DELETED",
        ]
    ] = Field(
        None,
        description="The lifecycle state of the load balancer to filter on",
    ),
    display_name: Optional[str] = Field(
        None, description="Exact display name to filter on"
    ),
    sort_by: Optional[Literal["TIMECREATED", "DISPLAYNAME"]] = Field(
        None, description="Field to sort by"
    ),
    sort_order: Optional[Literal["ASC", "DESC"]] = Field(
        None, description="Sort order to use"
    ),
) -> list[LoadBalancer]:
    lbs: list[LoadBalancer] = []

    try:
        client = get_load_balancer_client()

        response: oci.response.Response = None
        has_next_page = True
        next_page: str = None

        while has_next_page and (limit is None or len(lbs) < limit):
            kwargs = {
                "compartment_id": compartment_id,
                "page": next_page,
                "limit": limit,
            }

            if lifecycle_state is not None:
                kwargs["lifecycle_state"] = lifecycle_state
            if display_name is not None:
                kwargs["display_name"] = display_name
            if sort_by is not None:
                kwargs["sort_by"] = sort_by
            if sort_order is not None:
                kwargs["sort_order"] = sort_order

            response = client.list_load_balancers(**kwargs)
            has_next_page = getattr(response, "has_next_page", False)
            next_page = response.next_page if hasattr(response, "next_page") else None

            items = getattr(response.data, "items", response.data)
            for d in items:
                lbs.append(map_load_balancer(d))

        logger.info(f"Found {len(lbs)} Load Balancers")
        return lbs

    except Exception as e:
        logger.error(f"Error in list_load_balancers tool: {str(e)}")
        raise e


@mcp.tool(name="get_load_balancer", description="Get load balancer details")
def get_load_balancer(
    load_balancer_id: str = Field(..., description="The OCID of the load balancer")
) -> LoadBalancer:
    try:
        client = get_load_balancer_client()

        response: oci.response.Response = client.get_load_balancer(load_balancer_id)
        data: oci.load_balancer.models.LoadBalancer = response.data
        logger.info("Found Load Balancer")
        return map_load_balancer(data)

    except Exception as e:
        logger.error(f"Error in get_load_balancer tool: {str(e)}")
        raise e


@mcp.tool(name="create_load_balancer", description="Create a new load balancer")
def create_load_balancer(
    compartment_id: str = Field(
        ..., description="The OCID of the compartment to create the load balancer in."
    ),
    display_name: str = Field(
        ...,
        description="A user-friendly display name for the load balancer.",
        min_length=1,
        max_length=1024,
    ),
    shape_name: str = Field(
        ...,
        description="The shape name for the load balancer (e.g., Flexible, 100Mbps).",
    ),
    subnet_ids: list[str] = Field(
        ..., description="An array of subnet OCIDs for the load balancer."
    ),
    is_private: Optional[bool] = Field(
        None, description="Whether the load balancer should be private"
    ),
    ip_mode: Optional[Literal["IPV4", "IPV6"]] = Field(
        None, description="Whether the load balancer should have IPv4 or IPv6 address"
    ),
    is_delete_protection_enabled: Optional[bool] = Field(
        None, description="Enable delete protection for this load balancer"
    ),
    is_request_id_enabled: Optional[bool] = Field(
        None, description="Enable Request Id header feature for HTTP listeners"
    ),
    request_id_header: Optional[str] = Field(
        None, description="Custom header name for Request Id feature when enabled"
    ),
    network_security_group_ids: Optional[list[str]] = Field(
        None, description="Array of NSG OCIDs to associate with the load balancer"
    ),
    minimum_bandwidth_in_mbps: Optional[int] = Field(
        None, description="Minimum bandwidth in Mbps (Flexible shape only)"
    ),
    maximum_bandwidth_in_mbps: Optional[int] = Field(
        None, description="Maximum bandwidth in Mbps (Flexible shape only)"
    ),
) -> Response:
    try:
        client = get_load_balancer_client()

        shape_details = None
        if (
            minimum_bandwidth_in_mbps is not None
            and maximum_bandwidth_in_mbps is not None
        ):
            shape_details = oci.load_balancer.models.ShapeDetails(
                minimum_bandwidth_in_mbps=minimum_bandwidth_in_mbps,
                maximum_bandwidth_in_mbps=maximum_bandwidth_in_mbps,
            )

        details = oci.load_balancer.models.CreateLoadBalancerDetails(
            compartment_id=compartment_id,
            display_name=display_name,
            shape_name=shape_name,
            subnet_ids=subnet_ids,
            is_private=is_private,
            ip_mode=ip_mode,
            is_delete_protection_enabled=is_delete_protection_enabled,
            is_request_id_enabled=is_request_id_enabled,
            request_id_header=request_id_header,
            network_security_group_ids=network_security_group_ids,
            shape_details=shape_details,
        )

        response: oci.response.Response = client.create_load_balancer(details)
        logger.info("Create Load Balancer request accepted")
        return map_response(response)

    except Exception as e:
        logger.error(f"Error in create_load_balancer tool: {str(e)}")
        raise e


@mcp.tool(
    name="update_load_balancer", description="Update a load balancer configuration"
)
def update_load_balancer(
    load_balancer_id: str = Field(
        ..., description="The OCID of the load balancer to update"
    ),
    display_name: Optional[str] = Field(
        None, description="New display name for the load balancer"
    ),
    is_delete_protection_enabled: Optional[bool] = Field(
        None, description="Whether delete protection should be enabled"
    ),
    is_request_id_enabled: Optional[bool] = Field(
        None, description="Enable Request Id header feature for HTTP listeners"
    ),
    request_id_header: Optional[str] = Field(
        None, description="Custom header name for Request Id feature when enabled"
    ),
    freeform_tags: Optional[dict[str, str]] = Field(
        None, description="Free-form tags to set on the resource"
    ),
    defined_tags: Optional[dict[str, dict[str, object]]] = Field(
        None, description="Defined tags to set on the resource"
    ),
    defined_tags_extended: Optional[dict[str, dict[str, dict[str, object]]]] = Field(
        None, description="Extended defined tags to set on the resource"
    ),
) -> Response:
    try:
        client = get_load_balancer_client()

        update_details = oci.load_balancer.models.UpdateLoadBalancerDetails(
            display_name=display_name,
            is_delete_protection_enabled=is_delete_protection_enabled,
            is_request_id_enabled=is_request_id_enabled,
            request_id_header=request_id_header,
            freeform_tags=freeform_tags,
            defined_tags=defined_tags,
            defined_tags_extended=defined_tags_extended,
        )

        response: oci.response.Response = client.update_load_balancer(
            update_details, load_balancer_id
        )
        logger.info("Update Load Balancer request accepted")
        return map_response(response)

    except Exception as e:
        logger.error(f"Error in update_load_balancer tool: {str(e)}")
        raise e


@mcp.tool(name="delete_load_balancer", description="Delete a load balancer")
def delete_load_balancer(
    load_balancer_id: str = Field(
        ..., description="The OCID of the load balancer to delete"
    )
) -> Response:
    try:
        client = get_load_balancer_client()

        response: oci.response.Response = client.delete_load_balancer(load_balancer_id)
        logger.info("Delete Load Balancer request accepted")
        return map_response(response)

    except Exception as e:
        logger.error(f"Error in delete_load_balancer tool: {str(e)}")
        raise e


@mcp.tool(
    name="list_load_balancer_listeners",
    description="Lists the listeners from the given load balancer",
)
def list_load_balancer_listeners(
    load_balancer_id: str = Field(..., description="The OCID of the load balancer"),
    limit: Optional[int] = Field(
        None,
        description="The maximum number of listeners to return. If None, all listeners are returned.",
        ge=1,
    ),
) -> list[Listener]:
    try:
        client = get_load_balancer_client()
        response: oci.response.Response = client.get_load_balancer(load_balancer_id)
        lb: oci.load_balancer.models.LoadBalancer = response.data
        listeners_map = getattr(lb, "listeners", {}) or {}
        listeners: list[Listener] = []
        for _, l in listeners_map.items():
            listeners.append(map_listener(l))
            if limit is not None and len(listeners) >= limit:
                break
        logger.info(f"Found {len(listeners)} Listeners")
        return listeners
    except Exception as e:
        logger.error(f"Error in list_load_balancer_listeners tool: {str(e)}")
        raise e


@mcp.tool(
    name="create_load_balancer_listener",
    description="Adds a listener to a load balancer",
)
def create_load_balancer_listener(
    load_balancer_id: str = Field(..., description="The OCID of the load balancer"),
    name: str = Field(
        ...,
        description="A friendly name for the listener",
        min_length=1,
        max_length=255,
    ),
    default_backend_set_name: str = Field(
        ...,
        description="The name of the associated backend set",
        min_length=1,
        max_length=32,
    ),
    port: int = Field(
        ..., description="The communication port for the listener", ge=1, le=65535
    ),
    protocol: Literal["HTTP", "HTTP2", "TCP", "GRPC"] = Field(
        ...,
        description="The protocol on which the listener accepts connection requests",
    ),
    hostname_names: Optional[list[str]] = Field(
        None, description="An array of hostname resource names"
    ),
    path_route_set_name: Optional[str] = Field(
        None,
        description="Deprecated. Name of the PathRouteSet applied to this listener",
    ),
    routing_policy_name: Optional[str] = Field(
        None, description="Name of the RoutingPolicy applied to this listener"
    ),
    rule_set_names: Optional[list[str]] = Field(
        None, description="Names of RuleSets applied to this listener"
    ),
    # SSL configuration (common subset)
    ssl_protocols: Optional[list[str]] = Field(
        None, description="Supported SSL protocols (e.g., TLSv1.2, TLSv1.3)"
    ),
    ssl_cipher_suite_name: Optional[str] = Field(
        None, description="Cipher suite name to use for SSL/HTTPS"
    ),
    ssl_server_order_preference: Optional[Literal["ENABLED", "DISABLED"]] = Field(
        None, description="Preference for server ciphers over client ciphers"
    ),
    ssl_certificate_name: Optional[str] = Field(
        None, description="Certificate bundle name configured on the load balancer"
    ),
    ssl_has_session_resumption: Optional[bool] = Field(
        None, description="Whether TLS session resumption should be enabled"
    ),
    ssl_verify_peer_certificate: Optional[bool] = Field(
        None, description="Whether to verify peer certificates"
    ),
    ssl_verify_depth: Optional[int] = Field(
        None, description="Max depth for peer certificate chain verification"
    ),
    # Connection configuration
    idle_timeout: Optional[int] = Field(
        None,
        description="Maximum idle time in seconds between client/backend operations",
    ),
    backend_tcp_proxy_protocol_version: Optional[int] = Field(
        None, description="Backend TCP Proxy Protocol version (1 or 2)"
    ),
    backend_tcp_proxy_protocol_options: Optional[
        list[Literal["PP2_TYPE_AUTHORITY"]]
    ] = Field(None, description="PPv2 options that can be enabled on TCP listeners"),
) -> Response:
    try:
        client = get_load_balancer_client()

        ssl_cfg = None
        if any(
            x is not None
            for x in [
                ssl_protocols,
                ssl_cipher_suite_name,
                ssl_server_order_preference,
                ssl_certificate_name,
                ssl_has_session_resumption,
                ssl_verify_peer_certificate,
                ssl_verify_depth,
            ]
        ):
            ssl_cfg = oci.load_balancer.models.SSLConfigurationDetails(
                protocols=ssl_protocols,
                cipher_suite_name=ssl_cipher_suite_name,
                server_order_preference=ssl_server_order_preference,
                certificate_name=ssl_certificate_name,
                has_session_resumption=ssl_has_session_resumption,
                verify_peer_certificate=ssl_verify_peer_certificate,
                verify_depth=ssl_verify_depth,
            )

        conn_cfg = None
        if any(
            x is not None
            for x in [
                idle_timeout,
                backend_tcp_proxy_protocol_version,
                backend_tcp_proxy_protocol_options,
            ]
        ):
            conn_cfg = oci.load_balancer.models.ConnectionConfiguration(
                idle_timeout=idle_timeout,
                backend_tcp_proxy_protocol_version=backend_tcp_proxy_protocol_version,
                backend_tcp_proxy_protocol_options=backend_tcp_proxy_protocol_options,
            )

        details = oci.load_balancer.models.CreateListenerDetails(
            name=name,
            default_backend_set_name=default_backend_set_name,
            port=port,
            protocol=protocol,
            hostname_names=hostname_names,
            path_route_set_name=path_route_set_name,
            ssl_configuration=ssl_cfg,
            connection_configuration=conn_cfg,
            routing_policy_name=routing_policy_name,
            rule_set_names=rule_set_names,
        )

        response: oci.response.Response = client.create_listener(
            details, load_balancer_id
        )
        logger.info("Create Listener request accepted")
        return map_response(response)

    except Exception as e:
        logger.error(f"Error in create_load_balancer_listener tool: {str(e)}")
        raise e


@mcp.tool(
    name="get_load_balancer_listener",
    description="Gets a listener by name from the given load balancer",
)
def get_load_balancer_listener(
    load_balancer_id: str = Field(..., description="The OCID of the load balancer"),
    listener_name: str = Field(..., description="The name of the listener to fetch"),
) -> Listener:
    try:
        client = get_load_balancer_client()
        response: oci.response.Response = client.get_load_balancer(load_balancer_id)
        lb: oci.load_balancer.models.LoadBalancer = response.data
        listeners_map = getattr(lb, "listeners", {}) or {}
        raw = listeners_map.get(listener_name)
        if raw is None:
            raise ValueError(
                f"Listener '{listener_name}' not found on load balancer {load_balancer_id}"
            )
        return map_listener(raw)
    except Exception as e:
        logger.error(f"Error in get_load_balancer_listener tool: {str(e)}")
        raise e


@mcp.tool(
    name="update_load_balancer_listener",
    description="Updates a listener for a given load balancer",
)
def update_load_balancer_listener(
    load_balancer_id: str = Field(..., description="The OCID of the load balancer"),
    listener_name: str = Field(..., description="The name of the listener to update"),
    default_backend_set_name: Optional[str] = Field(
        None,
        description="The name of the associated backend set",
        min_length=1,
        max_length=32,
    ),
    port: Optional[int] = Field(
        None, description="The communication port for the listener", ge=1, le=65535
    ),
    protocol: Optional[Literal["HTTP", "HTTP2", "TCP", "GRPC"]] = Field(
        None,
        description="The protocol on which the listener accepts connection requests",
    ),
    hostname_names: Optional[list[str]] = Field(
        None, description="An array of hostname resource names"
    ),
    path_route_set_name: Optional[str] = Field(
        None,
        description="Deprecated. Name of the PathRouteSet applied to this listener",
    ),
    routing_policy_name: Optional[str] = Field(
        None, description="Name of the RoutingPolicy applied to this listener"
    ),
    rule_set_names: Optional[list[str]] = Field(
        None, description="Names of RuleSets applied to this listener"
    ),
    # SSL configuration (common subset)
    ssl_protocols: Optional[list[str]] = Field(
        None, description="Supported SSL protocols (e.g., TLSv1.2, TLSv1.3)"
    ),
    ssl_cipher_suite_name: Optional[str] = Field(
        None, description="Cipher suite name to use for SSL/HTTPS"
    ),
    ssl_server_order_preference: Optional[Literal["ENABLED", "DISABLED"]] = Field(
        None, description="Preference for server ciphers over client ciphers"
    ),
    ssl_certificate_name: Optional[str] = Field(
        None, description="Certificate bundle name configured on the load balancer"
    ),
    ssl_has_session_resumption: Optional[bool] = Field(
        None, description="Whether TLS session resumption should be enabled"
    ),
    ssl_verify_peer_certificate: Optional[bool] = Field(
        None, description="Whether to verify peer certificates"
    ),
    ssl_verify_depth: Optional[int] = Field(
        None, description="Max depth for peer certificate chain verification"
    ),
    # Connection configuration
    idle_timeout: Optional[int] = Field(
        None,
        description="Maximum idle time in seconds between client/backend operations",
    ),
    backend_tcp_proxy_protocol_version: Optional[int] = Field(
        None, description="Backend TCP Proxy Protocol version (1 or 2)"
    ),
    backend_tcp_proxy_protocol_options: Optional[
        list[Literal["PP2_TYPE_AUTHORITY"]]
    ] = Field(None, description="PPv2 options that can be enabled on TCP listeners"),
) -> Response:
    try:
        client = get_load_balancer_client()

        ssl_cfg = None
        if any(
            x is not None
            for x in [
                ssl_protocols,
                ssl_cipher_suite_name,
                ssl_server_order_preference,
                ssl_certificate_name,
                ssl_has_session_resumption,
                ssl_verify_peer_certificate,
                ssl_verify_depth,
            ]
        ):
            ssl_cfg = oci.load_balancer.models.SSLConfigurationDetails(
                protocols=ssl_protocols,
                cipher_suite_name=ssl_cipher_suite_name,
                server_order_preference=ssl_server_order_preference,
                certificate_name=ssl_certificate_name,
                has_session_resumption=ssl_has_session_resumption,
                verify_peer_certificate=ssl_verify_peer_certificate,
                verify_depth=ssl_verify_depth,
            )

        conn_cfg = None
        if any(
            x is not None
            for x in [
                idle_timeout,
                backend_tcp_proxy_protocol_version,
                backend_tcp_proxy_protocol_options,
            ]
        ):
            conn_cfg = oci.load_balancer.models.ConnectionConfiguration(
                idle_timeout=idle_timeout,
                backend_tcp_proxy_protocol_version=backend_tcp_proxy_protocol_version,
                backend_tcp_proxy_protocol_options=backend_tcp_proxy_protocol_options,
            )

        details = oci.load_balancer.models.UpdateListenerDetails(
            default_backend_set_name=default_backend_set_name,
            port=port,
            protocol=protocol,
            hostname_names=hostname_names,
            path_route_set_name=path_route_set_name,
            ssl_configuration=ssl_cfg,
            connection_configuration=conn_cfg,
            routing_policy_name=routing_policy_name,
            rule_set_names=rule_set_names,
        )

        response: oci.response.Response = client.update_listener(
            details, load_balancer_id, listener_name
        )
        logger.info("Update Listener request accepted")
        return map_response(response)

    except Exception as e:
        logger.error(f"Error in update_load_balancer_listener tool: {str(e)}")
        raise e


@mcp.tool(
    name="delete_load_balancer_listener",
    description="Deletes a listener from a load balancer",
)
def delete_load_balancer_listener(
    load_balancer_id: str = Field(..., description="The OCID of the load balancer"),
    listener_name: str = Field(..., description="The name of the listener to delete"),
) -> Response:
    try:
        client = get_load_balancer_client()
        response: oci.response.Response = client.delete_listener(
            load_balancer_id, listener_name
        )
        logger.info("Delete Listener request accepted")
        return map_response(response)
    except Exception as e:
        logger.error(f"Error in delete_load_balancer_listener tool: {str(e)}")
        raise e


@mcp.tool(
    name="list_load_balancer_backend_sets",
    description="Lists the backend sets from the given load balancer",
)
def list_load_balancer_backend_sets(
    load_balancer_id: str = Field(..., description="The OCID of the load balancer"),
    limit: Optional[int] = Field(
        None,
        description="The maximum number of backend sets to return. If None, all are returned.",
        ge=1,
    ),
) -> list[BackendSet]:
    try:
        client = get_load_balancer_client()
        backend_sets: list[BackendSet] = []
        response: oci.response.Response = None
        has_next_page = True
        next_page: str | None = None
        while has_next_page and (limit is None or len(backend_sets) < limit):
            response = client.list_backend_sets(
                load_balancer_id=load_balancer_id,
                page=next_page,
                limit=limit,
            )
            has_next_page = getattr(response, "has_next_page", False)
            next_page = response.next_page if hasattr(response, "next_page") else None
            items = getattr(response.data, "items", response.data) or []
            for d in items:
                backend_sets.append(map_backend_set(d))
                if limit is not None and len(backend_sets) >= limit:
                    break
        logger.info(f"Found {len(backend_sets)} Backend Sets")
        return backend_sets
    except Exception as e:
        logger.error(f"Error in list_load_balancer_backend_sets tool: {str(e)}")
        raise e


@mcp.tool(
    name="get_load_balancer_backend_set",
    description="Gets the backend set with the given name from the given load balancer",
)
def get_load_balancer_backend_set(
    load_balancer_id: str = Field(..., description="The OCID of the load balancer"),
    backend_set_name: str = Field(
        ..., description="The name of the backend set to fetch"
    ),
) -> BackendSet:
    try:
        client = get_load_balancer_client()
        response: oci.response.Response = client.get_backend_set(
            load_balancer_id, backend_set_name
        )
        data: oci.load_balancer.models.BackendSet = response.data
        logger.info("Found Backend Set")
        return map_backend_set(data)
    except Exception as e:
        logger.error(f"Error in get_load_balancer_backend_set tool: {str(e)}")
        raise e


@mcp.tool(
    name="create_load_balancer_backend_set",
    description="Adds a backend set to a load balancer",
)
def create_load_balancer_backend_set(
    load_balancer_id: str = Field(..., description="The OCID of the load balancer"),
    name: str = Field(
        ...,
        min_length=1,
        max_length=32,
        description="A friendly, unique backend set name",
    ),
    policy: str = Field(..., description="Load balancer policy for this backend set"),
    backends: Optional[list[Backend]] = Field(
        None, description="Backends to include in the backend set"
    ),
    backend_max_connections: Optional[int] = Field(
        None,
        description=(
            "Max simultaneous connections to any backend unless overridden at backend level"
        ),
        ge=256,
        le=65535,
    ),
    # Health checker
    health_checker_protocol: str = Field(
        ..., description="Protocol used for health checks (HTTP or TCP)"
    ),
    health_checker_url_path: Optional[str] = Field(
        None, description="Path for HTTP health checks"
    ),
    health_checker_port: Optional[int] = Field(
        None, description="Port to use for the health check", ge=0, le=65535
    ),
    health_checker_return_code: Optional[int] = Field(
        None, description="Expected return code from healthy backend"
    ),
    health_checker_retries: Optional[int] = Field(
        None, description="Number of retries before marking backend unhealthy"
    ),
    health_checker_timeout_in_millis: Optional[int] = Field(
        None,
        description="Timeout in milliseconds for health check replies",
        ge=1,
        le=600000,
    ),
    health_checker_interval_in_millis: Optional[int] = Field(
        None,
        description="Interval between health checks in milliseconds",
        ge=1000,
        le=1800000,
    ),
    health_checker_response_body_regex: Optional[str] = Field(
        None, description="Regex to match against HTTP response body"
    ),
    health_checker_is_force_plain_text: Optional[bool] = Field(
        None,
        description=(
            "Force plaintext health checks regardless of backend set SSL configuration"
        ),
    ),
    # SSL configuration
    ssl_protocols: Optional[list[str]] = Field(
        None, description="Supported SSL protocols (e.g., TLSv1.2, TLSv1.3)"
    ),
    ssl_cipher_suite_name: Optional[str] = Field(
        None, description="Cipher suite name for SSL configuration"
    ),
    ssl_server_order_preference: Optional[Literal["ENABLED", "DISABLED"]] = Field(
        None, description="Preference for server ciphers over client ciphers"
    ),
    ssl_certificate_name: Optional[str] = Field(
        None, description="Certificate bundle name configured on the load balancer"
    ),
    ssl_certificate_ids: Optional[list[str]] = Field(
        None, description="OCI Certificates service certificate OCIDs"
    ),
    ssl_trusted_certificate_authority_ids: Optional[list[str]] = Field(
        None, description="OCI Certificates CA/bundle OCIDs to trust"
    ),
    ssl_has_session_resumption: Optional[bool] = Field(
        None, description="Whether TLS session resumption should be enabled"
    ),
    ssl_verify_peer_certificate: Optional[bool] = Field(
        None, description="Whether to verify peer certificates"
    ),
    ssl_verify_depth: Optional[int] = Field(
        None, description="Max depth for peer certificate chain verification"
    ),
    # Session persistence (application cookie)
    session_persistence_cookie_name: Optional[str] = Field(
        None, description="Cookie name for application-cookie stickiness"
    ),
    session_persistence_disable_fallback: Optional[bool] = Field(
        None,
        description="Disable fallback to a different backend when original unavailable",
    ),
    # LB cookie persistence
    lb_cookie_cookie_name: Optional[str] = Field(
        None, description="Name of cookie inserted by the load balancer"
    ),
    lb_cookie_disable_fallback: Optional[bool] = Field(
        None, description="Disable fallback when original backend unavailable"
    ),
    lb_cookie_domain: Optional[str] = Field(None, description="Cookie domain"),
    lb_cookie_path: Optional[str] = Field(None, description="Cookie path"),
    lb_cookie_max_age_in_seconds: Optional[int] = Field(
        None, description="Cookie Max-Age in seconds"
    ),
    lb_cookie_is_secure: Optional[bool] = Field(
        None, description="Whether to set the Secure attribute on the cookie"
    ),
    lb_cookie_is_http_only: Optional[bool] = Field(
        None, description="Whether to set the HttpOnly attribute on the cookie"
    ),
) -> Response:
    try:
        client = get_load_balancer_client()

        # Health checker details
        health_checker = None
        if any(
            x is not None
            for x in [
                health_checker_url_path,
                health_checker_port,
                health_checker_return_code,
                health_checker_retries,
                health_checker_timeout_in_millis,
                health_checker_interval_in_millis,
                health_checker_response_body_regex,
                health_checker_is_force_plain_text,
            ]
        ):
            health_checker = oci.load_balancer.models.HealthCheckerDetails(
                protocol=health_checker_protocol,
                url_path=health_checker_url_path,
                port=health_checker_port,
                return_code=health_checker_return_code,
                retries=health_checker_retries,
                timeout_in_millis=health_checker_timeout_in_millis,
                interval_in_millis=health_checker_interval_in_millis,
                response_body_regex=health_checker_response_body_regex,
                is_force_plain_text=health_checker_is_force_plain_text,
            )

        # SSL configuration
        ssl_cfg = None
        if any(
            x is not None
            for x in [
                ssl_protocols,
                ssl_cipher_suite_name,
                ssl_server_order_preference,
                ssl_certificate_name,
                ssl_certificate_ids,
                ssl_trusted_certificate_authority_ids,
                ssl_has_session_resumption,
                ssl_verify_peer_certificate,
                ssl_verify_depth,
            ]
        ):
            ssl_cfg = oci.load_balancer.models.SSLConfigurationDetails(
                protocols=ssl_protocols,
                cipher_suite_name=ssl_cipher_suite_name,
                server_order_preference=ssl_server_order_preference,
                certificate_name=ssl_certificate_name,
                certificate_ids=ssl_certificate_ids,
                trusted_certificate_authority_ids=ssl_trusted_certificate_authority_ids,
                has_session_resumption=ssl_has_session_resumption,
                verify_peer_certificate=ssl_verify_peer_certificate,
                verify_depth=ssl_verify_depth,
            )

        # Session persistence
        session_persistence = None
        if any(
            x is not None
            for x in [
                session_persistence_cookie_name,
                session_persistence_disable_fallback,
            ]
        ):
            session_persistence = (
                oci.load_balancer.models.SessionPersistenceConfigurationDetails(
                    cookie_name=session_persistence_cookie_name,
                    disable_fallback=session_persistence_disable_fallback,
                )
            )

        # LB cookie persistence
        lb_cookie_persistence = None
        if any(
            x is not None
            for x in [
                lb_cookie_cookie_name,
                lb_cookie_disable_fallback,
                lb_cookie_domain,
                lb_cookie_path,
                lb_cookie_max_age_in_seconds,
                lb_cookie_is_secure,
                lb_cookie_is_http_only,
            ]
        ):
            lb_cookie_persistence = (
                oci.load_balancer.models.LBCookieSessionPersistenceConfigurationDetails(
                    cookie_name=lb_cookie_cookie_name,
                    disable_fallback=lb_cookie_disable_fallback,
                    domain=lb_cookie_domain,
                    path=lb_cookie_path,
                    max_age_in_seconds=lb_cookie_max_age_in_seconds,
                    is_secure=lb_cookie_is_secure,
                    is_http_only=lb_cookie_is_http_only,
                )
            )

        # Backend details conversion
        backend_details = None
        if backends is not None:
            backend_details = [
                oci.load_balancer.models.BackendDetails(
                    ip_address=b.ip_address,
                    port=b.port,
                    weight=b.weight,
                    max_connections=b.max_connections,
                    backup=b.backup,
                    drain=b.drain,
                    offline=b.offline,
                )
                for b in backends
            ]

        details = oci.load_balancer.models.CreateBackendSetDetails(
            name=name,
            policy=policy,
            backends=backend_details,
            backend_max_connections=backend_max_connections,
            health_checker=health_checker,
            ssl_configuration=ssl_cfg,
            session_persistence_configuration=session_persistence,
            lb_cookie_session_persistence_configuration=lb_cookie_persistence,
        )

        response: oci.response.Response = client.create_backend_set(
            details, load_balancer_id
        )
        logger.info("Create Backend Set request accepted")
        return map_response(response)

    except Exception as e:
        logger.error(f"Error in create_load_balancer_backend_set tool: {str(e)}")
        raise e


@mcp.tool(
    name="update_load_balancer_backend_set",
    description="Updates a backend set on a load balancer",
)
def update_load_balancer_backend_set(
    load_balancer_id: str = Field(..., description="The OCID of the load balancer"),
    name: str = Field(
        ...,
        min_length=1,
        max_length=32,
        description="The name of the backend set to update",
    ),
    policy: Optional[str] = Field(
        None, description="Load balancer policy for this backend set"
    ),
    backends: Optional[list[Backend]] = Field(
        None, description="Backends to include in the backend set"
    ),
    backend_max_connections: Optional[int] = Field(
        None,
        description=(
            "Max simultaneous connections to any backend unless overridden at backend level"
        ),
        ge=256,
        le=65535,
    ),
    # Health checker (same fields as create)
    health_checker_protocol: Optional[str] = Field(
        None, description="Protocol used for health checks (HTTP or TCP)"
    ),
    health_checker_url_path: Optional[str] = Field(
        None, description="Path for HTTP health checks"
    ),
    health_checker_port: Optional[int] = Field(
        None, description="Port to use for the health check", ge=0, le=65535
    ),
    health_checker_return_code: Optional[int] = Field(
        None, description="Expected return code from healthy backend"
    ),
    health_checker_retries: Optional[int] = Field(
        None, description="Number of retries before marking backend unhealthy"
    ),
    health_checker_timeout_in_millis: Optional[int] = Field(
        None,
        description="Timeout in milliseconds for health check replies",
        ge=1,
        le=600000,
    ),
    health_checker_interval_in_millis: Optional[int] = Field(
        None,
        description="Interval between health checks in milliseconds",
        ge=1000,
        le=1800000,
    ),
    health_checker_response_body_regex: Optional[str] = Field(
        None, description="Regex to match against HTTP response body"
    ),
    health_checker_is_force_plain_text: Optional[bool] = Field(
        None,
        description=(
            "Force plaintext health checks regardless of backend set SSL configuration"
        ),
    ),
    # SSL configuration
    ssl_protocols: Optional[list[str]] = Field(
        None, description="Supported SSL protocols (e.g., TLSv1.2, TLSv1.3)"
    ),
    ssl_cipher_suite_name: Optional[str] = Field(
        None, description="Cipher suite name for SSL configuration"
    ),
    ssl_server_order_preference: Optional[Literal["ENABLED", "DISABLED"]] = Field(
        None, description="Preference for server ciphers over client ciphers"
    ),
    ssl_certificate_name: Optional[str] = Field(
        None, description="Certificate bundle name configured on the load balancer"
    ),
    ssl_certificate_ids: Optional[list[str]] = Field(
        None, description="OCI Certificates service certificate OCIDs"
    ),
    ssl_trusted_certificate_authority_ids: Optional[list[str]] = Field(
        None, description="OCI Certificates CA/bundle OCIDs to trust"
    ),
    ssl_has_session_resumption: Optional[bool] = Field(
        None, description="Whether TLS session resumption should be enabled"
    ),
    ssl_verify_peer_certificate: Optional[bool] = Field(
        None, description="Whether to verify peer certificates"
    ),
    ssl_verify_depth: Optional[int] = Field(
        None, description="Max depth for peer certificate chain verification"
    ),
    # Session persistence (application cookie)
    session_persistence_cookie_name: Optional[str] = Field(
        None, description="Cookie name for application-cookie stickiness"
    ),
    session_persistence_disable_fallback: Optional[bool] = Field(
        None,
        description="Disable fallback to a different backend when original unavailable",
    ),
    # LB cookie persistence
    lb_cookie_cookie_name: Optional[str] = Field(
        None, description="Name of cookie inserted by the load balancer"
    ),
    lb_cookie_disable_fallback: Optional[bool] = Field(
        None, description="Disable fallback when original backend unavailable"
    ),
    lb_cookie_domain: Optional[str] = Field(None, description="Cookie domain"),
    lb_cookie_path: Optional[str] = Field(None, description="Cookie path"),
    lb_cookie_max_age_in_seconds: Optional[int] = Field(
        None, description="Cookie Max-Age in seconds"
    ),
    lb_cookie_is_secure: Optional[bool] = Field(
        None, description="Whether to set the Secure attribute on the cookie"
    ),
    lb_cookie_is_http_only: Optional[bool] = Field(
        None, description="Whether to set the HttpOnly attribute on the cookie"
    ),
) -> Response:
    try:
        client = get_load_balancer_client()

        # Health checker details
        health_checker = None
        if any(
            x is not None
            for x in [
                health_checker_url_path,
                health_checker_port,
                health_checker_return_code,
                health_checker_retries,
                health_checker_timeout_in_millis,
                health_checker_interval_in_millis,
                health_checker_response_body_regex,
                health_checker_is_force_plain_text,
            ]
        ):
            health_checker = oci.load_balancer.models.HealthCheckerDetails(
                protocol=health_checker_protocol,
                url_path=health_checker_url_path,
                port=health_checker_port,
                return_code=health_checker_return_code,
                retries=health_checker_retries,
                timeout_in_millis=health_checker_timeout_in_millis,
                interval_in_millis=health_checker_interval_in_millis,
                response_body_regex=health_checker_response_body_regex,
                is_force_plain_text=health_checker_is_force_plain_text,
            )

        # SSL configuration
        ssl_cfg = None
        if any(
            x is not None
            for x in [
                ssl_protocols,
                ssl_cipher_suite_name,
                ssl_server_order_preference,
                ssl_certificate_name,
                ssl_certificate_ids,
                ssl_trusted_certificate_authority_ids,
                ssl_has_session_resumption,
                ssl_verify_peer_certificate,
                ssl_verify_depth,
            ]
        ):
            ssl_cfg = oci.load_balancer.models.SSLConfigurationDetails(
                protocols=ssl_protocols,
                cipher_suite_name=ssl_cipher_suite_name,
                server_order_preference=ssl_server_order_preference,
                certificate_name=ssl_certificate_name,
                certificate_ids=ssl_certificate_ids,
                trusted_certificate_authority_ids=ssl_trusted_certificate_authority_ids,
                has_session_resumption=ssl_has_session_resumption,
                verify_peer_certificate=ssl_verify_peer_certificate,
                verify_depth=ssl_verify_depth,
            )

        # Session persistence
        session_persistence = None
        if any(
            x is not None
            for x in [
                session_persistence_cookie_name,
                session_persistence_disable_fallback,
            ]
        ):
            session_persistence = (
                oci.load_balancer.models.SessionPersistenceConfigurationDetails(
                    cookie_name=session_persistence_cookie_name,
                    disable_fallback=session_persistence_disable_fallback,
                )
            )

        # LB cookie persistence
        lb_cookie_persistence = None
        if any(
            x is not None
            for x in [
                lb_cookie_cookie_name,
                lb_cookie_disable_fallback,
                lb_cookie_domain,
                lb_cookie_path,
                lb_cookie_max_age_in_seconds,
                lb_cookie_is_secure,
                lb_cookie_is_http_only,
            ]
        ):
            lb_cookie_persistence = (
                oci.load_balancer.models.LBCookieSessionPersistenceConfigurationDetails(
                    cookie_name=lb_cookie_cookie_name,
                    disable_fallback=lb_cookie_disable_fallback,
                    domain=lb_cookie_domain,
                    path=lb_cookie_path,
                    max_age_in_seconds=lb_cookie_max_age_in_seconds,
                    is_secure=lb_cookie_is_secure,
                    is_http_only=lb_cookie_is_http_only,
                )
            )

        # Backend details conversion
        backend_details = None
        if backends is not None:
            backend_details = [
                oci.load_balancer.models.BackendDetails(
                    ip_address=b.ip_address,
                    port=b.port,
                    weight=b.weight,
                    max_connections=b.max_connections,
                    backup=b.backup,
                    drain=b.drain,
                    offline=b.offline,
                )
                for b in backends
            ]

        details = oci.load_balancer.models.UpdateBackendSetDetails(
            policy=policy,
            backends=backend_details,
            backend_max_connections=backend_max_connections,
            health_checker=health_checker,
            ssl_configuration=ssl_cfg,
            session_persistence_configuration=session_persistence,
            lb_cookie_session_persistence_configuration=lb_cookie_persistence,
        )

        response: oci.response.Response = client.update_backend_set(
            load_balancer_id, name, details
        )
        logger.info("Update Backend Set request accepted")
        return map_response(response)

    except Exception as e:
        logger.error(f"Error in update_load_balancer_backend_set tool: {str(e)}")
        raise e


@mcp.tool(
    name="delete_load_balancer_backend_set",
    description="Deletes a backend set from a load balancer",
)
def delete_load_balancer_backend_set(
    load_balancer_id: str = Field(..., description="The OCID of the load balancer"),
    name: str = Field(
        ...,
        min_length=1,
        max_length=32,
        description="The name of the backend set to delete",
    ),
) -> Response:
    try:
        client = get_load_balancer_client()
        response: oci.response.Response = client.delete_backend_set(
            load_balancer_id, name
        )
        logger.info("Delete Backend Set request accepted")
        return map_response(response)
    except Exception as e:
        logger.error(f"Error in delete_load_balancer_backend_set tool: {str(e)}")
        raise e


def main():

    host = os.getenv("ORACLE_MCP_HOST")
    port = os.getenv("ORACLE_MCP_PORT")

    if host and port:
        mcp.run(transport="http", host=host, port=int(port))
    else:
        mcp.run()


if __name__ == "__main__":
    main()
