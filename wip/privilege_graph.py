"""
Web Application Privilege Graph Engine
BloodHound-inspired access control analysis for web applications

This module provides graph-based analysis of:
- Privilege escalation paths
- IDOR vulnerabilities
- Role/permission misconfigurations
- Session and token security issues

CWE References:
- CWE-269: Improper Privilege Management
- CWE-284: Improper Access Control
- CWE-285: Improper Authorization
- CWE-639: Authorization Bypass Through User-Controlled Key (IDOR)
"""

import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set

try:
    import networkx as nx
    HAS_NETWORKX = True
except ImportError:
    HAS_NETWORKX = False


class NodeType(Enum):
    """Types of nodes in the privilege graph"""
    USER = "user"
    ROLE = "role"
    PERMISSION = "permission"
    RESOURCE = "resource"
    ENDPOINT = "endpoint"
    SESSION = "session"
    TOKEN = "token"
    GROUP = "group"


class EdgeType(Enum):
    """Types of relationships in the privilege graph"""
    HAS_ROLE = "has_role"
    MEMBER_OF = "member_of"
    GRANTS = "grants"
    ALLOWS = "allows"
    OWNS = "owns"
    CAN_ACCESS = "can_access"
    CAN_READ = "can_read"
    CAN_WRITE = "can_write"
    CAN_DELETE = "can_delete"
    ISSUED_TO = "issued_to"
    HAS_CLAIM = "has_claim"
    INHERITS_FROM = "inherits_from"
    ACCESSES = "accesses"  # Observed access (user accessed endpoint)


class PrivilegeLevel(Enum):
    """Standard privilege levels"""
    UNAUTHENTICATED = 0
    AUTHENTICATED = 1
    USER = 2
    MODERATOR = 3
    ADMIN = 4
    SUPERADMIN = 5


@dataclass
class GraphNode:
    """Represents a node in the privilege graph"""
    id: str
    node_type: NodeType
    name: str = ""
    privilege_level: int = 0
    properties: Dict = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return {
            'id': self.id,
            'type': self.node_type.value,
            'name': self.name or self.id,
            'privilege_level': self.privilege_level,
            'properties': self.properties
        }


@dataclass
class GraphEdge:
    """Represents a relationship in the privilege graph"""
    source: str
    target: str
    edge_type: EdgeType
    properties: Dict = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return {
            'source': self.source,
            'target': self.target,
            'type': self.edge_type.value,
            'properties': self.properties
        }


@dataclass
class PrivilegeEscalationPath:
    """Represents a discovered privilege escalation path"""
    path: List[str]
    path_type: str  # vertical, horizontal, role_confusion
    start_node: str
    end_node: str
    start_privilege: int
    end_privilege: int
    edges: List[Dict]
    risk_score: float
    description: str

    def to_finding(self) -> Dict:
        """Convert to Beatrix finding format"""
        severity_map = {
            (0, 4): 'CRITICAL',  # Unauth to admin
            (0, 3): 'CRITICAL',  # Unauth to moderator
            (1, 4): 'CRITICAL',  # Auth to admin
            (2, 4): 'HIGH',      # User to admin
            (2, 3): 'MEDIUM',    # User to moderator
        }

        severity = severity_map.get(
            (self.start_privilege, self.end_privilege),
            'HIGH' if self.end_privilege >= 3 else 'MEDIUM'
        )

        return {
            'severity': severity,
            'type': f'Privilege Escalation ({self.path_type})',
            'cwe': 'CWE-269',
            'path': self.path,
            'path_length': len(self.path) - 1,
            'edges': self.edges,
            'start_privilege': self.start_privilege,
            'end_privilege': self.end_privilege,
            'risk_score': self.risk_score,
            'description': self.description,
            'impact': f'Escalation from level {self.start_privilege} to {self.end_privilege}',
            'recommendation': 'Implement proper authorization checks along the access path'
        }


class WebAppPrivilegeGraph:
    """
    BloodHound-inspired privilege graph for web applications.

    Uses NetworkX for graph operations to enable:
    - Path finding between privilege levels
    - Cycle detection (circular permissions)
    - Strongly connected components analysis
    - Shortest path to privilege escalation

    Example usage:
        graph = WebAppPrivilegeGraph()

        # Add discovered users and roles
        graph.add_user("user:john", roles=["member"], privilege_level=2)
        graph.add_user("user:admin", roles=["admin"], privilege_level=4)
        graph.add_role("role:member", privilege_level=2)
        graph.add_role("role:admin", privilege_level=4)

        # Add discovered endpoints
        graph.add_endpoint("/api/admin", methods=["GET"], auth_level=4)
        graph.add_endpoint("/api/roles", methods=["PUT"], auth_level=1)

        # Add access relationships discovered during scan
        graph.add_access("role:member", "/api/roles", "can_write")
        graph.add_access("role:admin", "/api/admin", "can_access")

        # Find escalation paths
        paths = graph.find_escalation_paths("user:john", min_target_level=4)
    """

    def __init__(self):
        if not HAS_NETWORKX:
            raise ImportError("networkx is required for privilege graph analysis. Install with: pip install networkx")

        self.graph = nx.DiGraph()
        self.nodes: Dict[str, GraphNode] = {}
        self.edges: List[GraphEdge] = []

    def add_user(self, user_id: str, name: str = "", roles: List[str] = None,
                 privilege_level: int = 2, properties: Dict = None):
        """Add a user node to the graph"""
        node = GraphNode(
            id=user_id,
            node_type=NodeType.USER,
            name=name or user_id,
            privilege_level=privilege_level,
            properties=properties or {}
        )
        self.nodes[user_id] = node
        self.graph.add_node(user_id, **node.to_dict())

        # Add role relationships
        if roles:
            for role in roles:
                role_id = f"role:{role}" if not role.startswith("role:") else role
                self.add_relationship(user_id, role_id, EdgeType.HAS_ROLE)

    def add_role(self, role_id: str, name: str = "", privilege_level: int = 2,
                 permissions: List[str] = None, inherits_from: List[str] = None,
                 properties: Dict = None):
        """Add a role node to the graph"""
        node = GraphNode(
            id=role_id,
            node_type=NodeType.ROLE,
            name=name or role_id,
            privilege_level=privilege_level,
            properties=properties or {}
        )
        self.nodes[role_id] = node
        self.graph.add_node(role_id, **node.to_dict())

        # Add permission grants
        if permissions:
            for perm in permissions:
                perm_id = f"permission:{perm}" if not perm.startswith("permission:") else perm
                self.add_relationship(role_id, perm_id, EdgeType.GRANTS)

        # Add role inheritance
        if inherits_from:
            for parent_role in inherits_from:
                parent_id = f"role:{parent_role}" if not parent_role.startswith("role:") else parent_role
                self.add_relationship(role_id, parent_id, EdgeType.INHERITS_FROM)

    def add_permission(self, permission_id: str, name: str = "",
                       resources: List[str] = None, properties: Dict = None):
        """Add a permission node to the graph"""
        node = GraphNode(
            id=permission_id,
            node_type=NodeType.PERMISSION,
            name=name or permission_id,
            properties=properties or {}
        )
        self.nodes[permission_id] = node
        self.graph.add_node(permission_id, **node.to_dict())

        # Add resource access
        if resources:
            for resource in resources:
                res_id = f"resource:{resource}" if not resource.startswith("resource:") else resource
                self.add_relationship(permission_id, res_id, EdgeType.ALLOWS)

    def add_resource(self, resource_id: str, name: str = "", path: str = "",
                     required_level: int = 0, owner: str = None, properties: Dict = None):
        """Add a resource node to the graph"""
        props = properties or {}
        props['path'] = path
        props['required_level'] = required_level

        node = GraphNode(
            id=resource_id,
            node_type=NodeType.RESOURCE,
            name=name or resource_id,
            privilege_level=required_level,
            properties=props
        )
        self.nodes[resource_id] = node
        self.graph.add_node(resource_id, **node.to_dict())

        if owner:
            owner_id = f"user:{owner}" if not owner.startswith("user:") else owner
            self.add_relationship(owner_id, resource_id, EdgeType.OWNS)

    def add_endpoint(self, endpoint: str, methods: List[str] = None,
                     auth_required: bool = True, required_level: int = 1,
                     properties: Dict = None):
        """Add an endpoint node to the graph"""
        endpoint_id = f"endpoint:{endpoint}"

        props = properties or {}
        props['methods'] = methods or ['GET']
        props['auth_required'] = auth_required

        node = GraphNode(
            id=endpoint_id,
            node_type=NodeType.ENDPOINT,
            name=endpoint,
            privilege_level=required_level if auth_required else 0,
            properties=props
        )
        self.nodes[endpoint_id] = node
        self.graph.add_node(endpoint_id, **node.to_dict())

    def add_token(self, token_id: str, user: str, claims: Dict = None,
                  expires: str = None, properties: Dict = None):
        """Add a JWT/token node to the graph"""
        props = properties or {}
        props['claims'] = claims or {}
        props['expires'] = expires

        node = GraphNode(
            id=token_id,
            node_type=NodeType.TOKEN,
            name=f"Token for {user}",
            properties=props
        )
        self.nodes[token_id] = node
        self.graph.add_node(token_id, **node.to_dict())

        # Link token to user
        user_id = f"user:{user}" if not user.startswith("user:") else user
        self.add_relationship(token_id, user_id, EdgeType.ISSUED_TO)

        # Add claim edges
        if claims:
            for claim_key, claim_value in claims.items():
                if claim_key in ['role', 'roles', 'permissions', 'scope']:
                    # These are privilege-related claims
                    if isinstance(claim_value, list):
                        for val in claim_value:
                            self.add_relationship(
                                token_id, f"permission:{val}",
                                EdgeType.HAS_CLAIM,
                                properties={'claim': claim_key}
                            )
                    else:
                        self.add_relationship(
                            token_id, f"permission:{claim_value}",
                            EdgeType.HAS_CLAIM,
                            properties={'claim': claim_key}
                        )

    def add_relationship(self, source: str, target: str, edge_type: EdgeType,
                        properties: Dict = None):
        """Add a relationship between nodes"""
        # Ensure target node exists (create placeholder if needed)
        if target not in self.nodes:
            # Infer node type from ID prefix
            if target.startswith("role:"):
                self.add_role(target)
            elif target.startswith("permission:"):
                self.add_permission(target)
            elif target.startswith("resource:"):
                self.add_resource(target)
            elif target.startswith("endpoint:"):
                self.add_endpoint(target.replace("endpoint:", ""))

        edge = GraphEdge(
            source=source,
            target=target,
            edge_type=edge_type,
            properties=properties or {}
        )
        self.edges.append(edge)
        self.graph.add_edge(source, target, **edge.to_dict())

    def add_access(self, subject: str, resource: str, access_type: str = "can_access"):
        """Convenience method to add access relationship"""
        edge_map = {
            'can_access': EdgeType.CAN_ACCESS,
            'can_read': EdgeType.CAN_READ,
            'can_write': EdgeType.CAN_WRITE,
            'can_delete': EdgeType.CAN_DELETE,
        }
        edge_type = edge_map.get(access_type, EdgeType.CAN_ACCESS)
        self.add_relationship(subject, resource, edge_type)

    def record_access(self, user_id: str, endpoint: str, status_code: int = 200,
                      method: str = "GET"):
        """
        Record an observed access event (user accessed endpoint).

        This is used to track actual runtime access patterns for BAC detection.
        When a low-privilege user successfully accesses a high-privilege endpoint,
        this will be flagged by find_broken_access_control().

        Args:
            user_id: The user ID (looks up both 'id' and 'user:id' formats)
            endpoint: The endpoint path accessed
            status_code: HTTP response status code
            method: HTTP method used
        """
        # Find the actual user node ID (handle both 'id' and 'user:id' formats)
        actual_user_id = None
        if user_id in self.nodes:
            actual_user_id = user_id
        elif f"user:{user_id}" in self.nodes:
            actual_user_id = f"user:{user_id}"
        elif user_id.startswith("user:") and user_id[5:] in self.nodes:
            actual_user_id = user_id[5:]
        else:
            # User not in graph, use prefixed format
            actual_user_id = f"user:{user_id}" if not user_id.startswith("user:") else user_id

        # Normalize endpoint ID
        endpoint_id = f"endpoint:{endpoint}"

        # Ensure endpoint exists
        if endpoint_id not in self.nodes:
            self.add_endpoint(endpoint, methods=[method])

        # Add access edge with status
        self.add_relationship(
            actual_user_id,
            endpoint_id,
            EdgeType.ACCESSES,
            properties={'status': status_code, 'method': method}
        )

    def find_escalation_paths(self, from_node: str,
                              min_target_level: int = 3,
                              max_hops: int = 5) -> List[PrivilegeEscalationPath]:
        """
        Find all privilege escalation paths from a node to high-privilege resources.

        Args:
            from_node: Starting node (usually a user)
            min_target_level: Minimum privilege level to consider as escalation target
            max_hops: Maximum path length to search

        Returns:
            List of PrivilegeEscalationPath objects
        """
        paths = []
        start_level = self.nodes.get(from_node, GraphNode(from_node, NodeType.USER)).privilege_level

        # Find all high-privilege nodes
        high_priv_nodes = [
            node_id for node_id, node in self.nodes.items()
            if node.privilege_level >= min_target_level
        ]

        for target in high_priv_nodes:
            try:
                # Find all simple paths
                all_paths = list(nx.all_simple_paths(
                    self.graph, from_node, target, cutoff=max_hops
                ))

                for path in all_paths:
                    # Get edges along path
                    edges = []
                    for i in range(len(path) - 1):
                        edge_data = self.graph.get_edge_data(path[i], path[i+1])
                        edges.append({
                            'from': path[i],
                            'to': path[i+1],
                            'type': edge_data.get('type', 'unknown')
                        })

                    target_level = self.nodes[target].privilege_level

                    # Calculate risk score
                    risk_score = self._calculate_risk_score(
                        start_level, target_level, len(path), edges
                    )

                    # Determine path type
                    if target_level > start_level + 1:
                        path_type = "vertical"
                    elif start_level == target_level:
                        path_type = "horizontal"
                    else:
                        path_type = "elevation"

                    paths.append(PrivilegeEscalationPath(
                        path=path,
                        path_type=path_type,
                        start_node=from_node,
                        end_node=target,
                        start_privilege=start_level,
                        end_privilege=target_level,
                        edges=edges,
                        risk_score=risk_score,
                        description=f"Path from {from_node} to {target} via {len(edges)} hops"
                    ))

            except nx.NetworkXNoPath:
                continue

        # Sort by risk score
        paths.sort(key=lambda p: p.risk_score, reverse=True)
        return paths

    def find_idor_risks(self) -> List[Dict]:
        """
        Find potential IDOR vulnerabilities.

        Identifies cases where:
        - User A can access resources owned by User B
        - Resources have predictable identifiers
        - Access checks may be missing
        """
        risks = []

        # Find all resources with owners
        for node_id, node in self.nodes.items():
            if node.node_type != NodeType.RESOURCE:
                continue

            # Find owners (nodes with OWNS edge to this resource)
            owners = set()
            accessors = set()

            for predecessor in self.graph.predecessors(node_id):
                edge_data = self.graph.get_edge_data(predecessor, node_id)
                if not edge_data:
                    continue
                if edge_data.get('type') == EdgeType.OWNS.value:
                    owners.add(predecessor)
                elif edge_data.get('type') in [
                    EdgeType.CAN_ACCESS.value,
                    EdgeType.CAN_READ.value,
                    EdgeType.CAN_WRITE.value
                ]:
                    accessors.add(predecessor)

            # Check for unauthorized access
            for accessor in accessors:
                if accessor not in owners:
                    # Expand to check if accessor inherits from owner's role
                    if not self._has_legitimate_access(accessor, owners):
                        risks.append({
                            'type': 'IDOR',
                            'severity': 'HIGH',
                            'cwe': 'CWE-639',
                            'resource': node_id,
                            'resource_path': node.properties.get('path', ''),
                            'owners': list(owners),
                            'unauthorized_accessor': accessor,
                            'description': f'{accessor} can access {node_id} without ownership',
                            'recommendation': 'Implement object-level authorization checks'
                        })

        return risks

    def find_role_confusion(self) -> List[Dict]:
        """
        Find role/permission confusion issues.

        Identifies cases where:
        - Token claims don't match role permissions
        - Circular role inheritance
        - Privilege level inconsistencies
        """
        issues = []

        # Check for circular role inheritance
        try:
            cycles = list(nx.simple_cycles(self.graph))
            for cycle in cycles:
                if all(self.nodes.get(n, GraphNode(n, NodeType.ROLE)).node_type == NodeType.ROLE
                       for n in cycle):
                    issues.append({
                        'type': 'Circular Role Inheritance',
                        'severity': 'MEDIUM',
                        'cwe': 'CWE-269',
                        'cycle': cycle,
                        'description': f'Circular role inheritance detected: {" → ".join(cycle)}',
                        'recommendation': 'Review and fix role hierarchy to remove cycles'
                    })
        except Exception:
            pass  # Graph may not have cycles

        # Check token claims vs role permissions
        for node_id, node in self.nodes.items():
            if node.node_type != NodeType.TOKEN:
                continue

            token_claims = set()
            role_permissions = set()

            # Get claims from token
            for successor in self.graph.successors(node_id):
                edge_data = self.graph.get_edge_data(node_id, successor)
                if not edge_data:
                    continue
                if edge_data.get('type') == EdgeType.HAS_CLAIM.value:
                    token_claims.add(successor)
                elif edge_data.get('type') == EdgeType.ISSUED_TO.value:
                    # Get user's role permissions
                    user = successor
                    for user_edge in self.graph.successors(user):
                        ue_data = self.graph.get_edge_data(user, user_edge)
                        if ue_data and ue_data.get('type') == EdgeType.HAS_ROLE.value:
                            # Get permissions from role
                            for role_edge in self.graph.successors(user_edge):
                                re_data = self.graph.get_edge_data(user_edge, role_edge)
                                if re_data and re_data.get('type') == EdgeType.GRANTS.value:
                                    role_permissions.add(role_edge)

            # Compare
            extra_in_token = token_claims - role_permissions
            if extra_in_token:
                issues.append({
                    'type': 'Token Claim Escalation',
                    'severity': 'CRITICAL',
                    'cwe': 'CWE-285',
                    'token': node_id,
                    'extra_claims': list(extra_in_token),
                    'description': 'Token contains claims not granted by user roles',
                    'recommendation': 'Validate token claims against actual role permissions'
                })

        return issues

    def find_unauthenticated_access(self) -> List[Dict]:
        """Find resources/endpoints accessible without authentication"""
        issues = []

        # Check endpoints
        for node_id, node in self.nodes.items():
            if node.node_type != NodeType.ENDPOINT:
                continue

            if not node.properties.get('auth_required', True):
                if node.privilege_level > 0:
                    issues.append({
                        'type': 'Unauthenticated Access to Protected Resource',
                        'severity': 'CRITICAL',
                        'cwe': 'CWE-306',
                        'endpoint': node.name,
                        'required_level': node.privilege_level,
                        'description': f'Endpoint {node.name} requires level {node.privilege_level} but has no auth',
                        'recommendation': 'Add authentication middleware to this endpoint'
                    })

        return issues

    def find_broken_access_control(self) -> List[Dict]:
        """
        Find Broken Access Control (BAC) issues where users access endpoints
        above their privilege level.

        This is a critical security check that detects when:
        - A low-privilege user can access admin-only endpoints
        - A user accesses resources requiring higher privilege levels
        - There's a mismatch between user role and endpoint requirements

        Returns:
            List of BAC findings with severity and remediation advice
        """
        issues = []

        # Find all CAN_ACCESS edges from users to endpoints
        for edge in self.edges:
            if edge.edge_type not in [EdgeType.CAN_ACCESS, EdgeType.ACCESSES]:
                continue

            source_node = self.nodes.get(edge.source)
            target_node = self.nodes.get(edge.target)

            if not source_node or not target_node:
                continue

            # Check if source is a user/token and target is an endpoint
            if source_node.node_type not in [NodeType.USER, NodeType.TOKEN]:
                continue
            if target_node.node_type != NodeType.ENDPOINT:
                continue

            # Check for privilege level mismatch
            user_level = source_node.privilege_level
            endpoint_level = target_node.privilege_level

            if user_level < endpoint_level:
                # BAC detected!
                level_diff = endpoint_level - user_level

                # Determine severity based on privilege gap
                if level_diff >= 3:
                    severity = 'CRITICAL'
                elif level_diff >= 2:
                    severity = 'HIGH'
                else:
                    severity = 'MEDIUM'

                # Get user info for better reporting
                user_roles = source_node.properties.get('roles', [])
                user_email = source_node.properties.get('email', 'unknown')
                status_code = edge.properties.get('status', 200)

                issues.append({
                    'type': 'Broken Access Control',
                    'severity': severity,
                    'cwe': 'CWE-639',
                    'user': source_node.name,
                    'user_id': source_node.id,
                    'user_privilege_level': user_level,
                    'user_roles': user_roles,
                    'user_email': user_email,
                    'endpoint': target_node.name,
                    'endpoint_id': target_node.id,
                    'required_privilege_level': endpoint_level,
                    'privilege_gap': level_diff,
                    'http_status': status_code,
                    'description': (
                        f"User '{source_node.name}' with privilege level {user_level} "
                        f"(roles: {user_roles}) accessed endpoint '{target_node.name}' "
                        f"which requires privilege level {endpoint_level}"
                    ),
                    'recommendation': (
                        'Implement proper access control checks that verify user roles/privileges '
                        'before granting access to protected endpoints. Consider using role-based '
                        'access control (RBAC) middleware.'
                    ),
                    'evidence': {
                        'endpoint_accessed': target_node.name,
                        'user_role': user_roles[0] if user_roles else 'unknown',
                        'response_status': status_code
                    }
                })

        return issues

    def analyze_all(self, focus_user: str = None) -> Dict:
        """
        Run all analysis methods and return comprehensive results.

        Args:
            focus_user: If provided, focus escalation analysis on this user

        Returns:
            Dict with all findings organized by type
        """
        results = {
            'summary': {
                'total_nodes': len(self.nodes),
                'total_edges': len(self.edges),
                'users': len([n for n in self.nodes.values() if n.node_type == NodeType.USER]),
                'roles': len([n for n in self.nodes.values() if n.node_type == NodeType.ROLE]),
                'resources': len([n for n in self.nodes.values() if n.node_type == NodeType.RESOURCE]),
                'endpoints': len([n for n in self.nodes.values() if n.node_type == NodeType.ENDPOINT]),
            },
            'escalation_paths': [],
            'idor_risks': [],
            'role_confusion': [],
            'unauthenticated_access': [],
            'total_findings': 0
        }

        # Escalation paths
        if focus_user:
            paths = self.find_escalation_paths(focus_user)
            results['escalation_paths'] = [p.to_finding() for p in paths]
        else:
            # Check all users
            for node_id, node in self.nodes.items():
                if node.node_type == NodeType.USER and node.privilege_level < 4:
                    paths = self.find_escalation_paths(node_id)
                    results['escalation_paths'].extend([p.to_finding() for p in paths])

        # IDOR
        results['idor_risks'] = self.find_idor_risks()

        # Role confusion
        results['role_confusion'] = self.find_role_confusion()

        # Unauth access
        results['unauthenticated_access'] = self.find_unauthenticated_access()

        # Broken Access Control (BAC)
        results['broken_access_control'] = self.find_broken_access_control()

        # Total
        results['total_findings'] = (
            len(results['escalation_paths']) +
            len(results['idor_risks']) +
            len(results['role_confusion']) +
            len(results['unauthenticated_access']) +
            len(results['broken_access_control'])
        )

        return results

    def _calculate_risk_score(self, start_level: int, end_level: int,
                             path_length: int, edges: List[Dict]) -> float:
        """Calculate risk score for an escalation path"""
        # Base score from privilege difference
        level_diff = end_level - start_level
        base_score = level_diff * 20

        # Shorter paths are more dangerous
        path_penalty = max(0, 10 - path_length * 2)

        # Certain edge types are more risky
        risky_edges = ['can_write', 'can_delete', 'has_claim']
        edge_bonus = sum(5 for e in edges if e.get('type') in risky_edges)

        return min(100, base_score + path_penalty + edge_bonus)

    def _has_legitimate_access(self, accessor: str, owners: Set[str]) -> bool:
        """Check if accessor has legitimate access through role hierarchy"""
        # Check if accessor shares a role with any owner
        accessor_roles = set()
        owner_roles = set()

        for successor in self.graph.successors(accessor):
            ed = self.graph.get_edge_data(accessor, successor)
            if ed and ed.get('type') == EdgeType.HAS_ROLE.value:
                accessor_roles.add(successor)

        for owner in owners:
            for successor in self.graph.successors(owner):
                ed = self.graph.get_edge_data(owner, successor)
                if ed and ed.get('type') == EdgeType.HAS_ROLE.value:
                    owner_roles.add(successor)

        # If they share an admin role, access is legitimate
        shared_roles = accessor_roles & owner_roles
        for role in shared_roles:
            if self.nodes.get(role, GraphNode(role, NodeType.ROLE)).privilege_level >= 3:
                return True

        return False

    def export_to_json(self) -> str:
        """Export graph to JSON format"""
        data = {
            'nodes': [n.to_dict() for n in self.nodes.values()],
            'edges': [e.to_dict() for e in self.edges]
        }
        return json.dumps(data, indent=2)

    def export_to_cypher(self) -> str:
        """Export graph as Cypher CREATE statements (for Neo4j/BloodHound)"""
        statements = []

        # Create nodes
        for node in self.nodes.values():
            label = node.node_type.value.title().replace('_', '')
            props = json.dumps(node.properties) if node.properties else '{}'
            statements.append(
                f"CREATE (:{label} {{id: '{node.id}', name: '{node.name}', "
                f"privilege_level: {node.privilege_level}, properties: {props}}})"
            )

        # Create relationships
        for edge in self.edges:
            rel_type = edge.edge_type.value.upper()
            statements.append(
                f"MATCH (a {{id: '{edge.source}'}}), (b {{id: '{edge.target}'}}) "
                f"CREATE (a)-[:{rel_type}]->(b)"
            )

        return ";\n".join(statements) + ";"

    def visualize(self, output_path: str = None) -> Optional[str]:
        """
        Generate a visualization of the privilege graph.
        Requires matplotlib and pygraphviz for best results.
        """
        try:
            import matplotlib.pyplot as plt

            # Create figure
            fig, ax = plt.subplots(1, 1, figsize=(12, 8))

            # Color nodes by type
            color_map = {
                NodeType.USER: '#4CAF50',
                NodeType.ROLE: '#2196F3',
                NodeType.PERMISSION: '#FFC107',
                NodeType.RESOURCE: '#E91E63',
                NodeType.ENDPOINT: '#9C27B0',
                NodeType.TOKEN: '#00BCD4',
            }

            colors = [color_map.get(self.nodes[n].node_type, '#888888')
                     for n in self.graph.nodes()]

            # Draw
            pos = nx.spring_layout(self.graph, k=2, iterations=50)
            nx.draw(self.graph, pos, ax=ax, node_color=colors,
                   with_labels=True, font_size=8, node_size=500,
                   arrows=True, arrowsize=10)

            plt.title("Web Application Privilege Graph")

            if output_path:
                plt.savefig(output_path, dpi=150, bbox_inches='tight')
                return output_path
            else:
                plt.show()
                return None

        except ImportError:
            return None
