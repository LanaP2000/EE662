import random
from enum import Enum
import sys

# insert at 1, 0 is the script path (or '' in REPL)
sys.path.insert(1, '.')
from source import wsnlab_vis as wsn
import math
from source import config

Roles = Enum('Roles', 'UNDISCOVERED UNREGISTERED ROOT REGISTERED CLUSTER_HEAD')
"""Enumeration of roles"""


###########################################################
class SensorNode(wsn.Node):
    """SensorNode class is inherited from Node class in wsnlab.py.
    It will run data collection tree construction algorithms.

    Attributes:
        role (Roles): role of node
        is_root_eligible (bool): eligibility to be root
        c_probe (int): probe message counter
        th_probe (int): probe message threshold
        neighbors_table (Dict): keeps the neighbor information with received heart beat messages
    """

    ###################
    def init(self):
        """Initialization of node. Setting all attributes of node.
        At the beginning node needs to be sleeping and its role should be UNDISCOVERED.

        Args:

        Returns:

        """
        self.scene.nodecolor(self.id, 1, 1, 1)  # sets self color to white
        self.sleep()
        self.addr = None
        self.ch_addr = None
        self.parent_gui = None
        self.root_addr = None
        self.role = Roles.UNDISCOVERED
        self.is_root_eligible = True if self.id == ROOT_ID else False
        self.c_probe = 0  # c means counter and probe is the name of counter
        self.th_probe = 10  # th means threshold and probe is the name of threshold
        self.hop_count = 99999
        self.neighbors_table = {}  # keeps neighbor information with received HB messages
        self.candidate_parents_table = []
        self.child_networks_table = {}
        self.members_table = []
        self.received_JR_guis = None
        self.heart_beat_disable = False
        self.multicast_channel_IDs = []
        self.isSubscriber = False
        self.isPublisher = False
        self.publishAddress = None
        self.PUBLISHER = [(2, wsn.Addr(254, 2))]
        self.LISTENERS = [3, 7, 10, 12]
        for gui in self.LISTENERS:
            if gui == self.id:
                self.isSubscriber = True
        for gui, address in self.PUBLISHER:
            if gui == self.id:
                self.isPublisher = True
                self.publishAddress = address
                print('I,', self.id, 'am publishing')

    ###################
    def run(self):
        """Setting the arrival timer to wake up and dead timer to die.

        Args:

        Returns:

        """
        self.set_timer('TIMER_ARRIVAL', self.arrival)

        if self.id != ROOT_ID:
            rand = random.randint(0, 10)
            if rand % 5 == 1:
                self.set_timer('TIMER_DEAD', 300)

    ###################
    def become_unregistered(self):
        """ Resets all necessary variables to be unregistered and becomes unregistered.

        Args:

        Returns:

        """
        if self.role != Roles.UNDISCOVERED:
            self.kill_all_timers()
            self.log('I became UNREGISTERED')
        self.child_networks_table = {}
        if self.parent_gui is not None:
            self.send_network_update()
        self.scene.nodecolor(self.id, 1, 1, 0)
        self.erase_parent()
        self.addr = None
        self.ch_addr = None
        self.parent_gui = None
        self.root_addr = None
        self.role = Roles.UNREGISTERED
        self.c_probe = 0
        self.th_probe = 10
        self.hop_count = 99999
        self.neighbors_table = {}
        self.candidate_parents_table = []
        self.members_table = []
        self.send_probe()
        self.set_timer('TIMER_JOIN_REQUEST', 20)
        self.send_network_update()

    ###################
    def set_colors(self):
        # ROOT
        if self.role == Roles.ROOT:
            self.scene.nodecolor(self.id, 0, 0, 0)  # black
        # Subscriber
        elif self.isSubscriber and self.role != Roles.ROOT:
            self.scene.nodecolor(self.id, 1, 0, 0) # red
        # Publisher
        elif self.isPublisher and self.role != Roles.ROOT:
            self.scene.nodecolor(self.id, 0, 1, 1) # light blue
        # CLUSTERHEAD
        elif self.role == Roles.CLUSTER_HEAD:
            self.scene.nodecolor(self.id, 0, 0, 1)  # blue
        # REGISTERED NODE
        elif self.role == Roles.REGISTERED:
            if len(self.members_table) != 0:  # ROUTER
                self.scene.nodecolor(self.id, 1, 0, 1)  # purple
            else:  # A REGULAR REGISTERED NODE
                self.scene.nodecolor(self.id, 0, 1, 0)  # green
        # UNREGISTERED NODE
        elif self.role == Roles.UNREGISTERED:
            self.scene.nodecolor(self.id, 1, 1, 0)  # yellow

    ###################
    def update_neighbor(self, pck):
        """Updates neighbor, child_network, members and candidate parent tables with incoming heartbeat package.

        Args:
            pck (Dict): heartbeat package
        Returns:

        """
        pck['arrival_time'] = self.now
        self.neighbors_table[pck['gui']] = pck
        if pck['gui'] not in self.child_networks_table.keys() or pck['gui'] not in self.members_table:
            if pck['gui'] not in self.candidate_parents_table:
                self.candidate_parents_table.append(pck['gui'])
        if pck['gui'] == self.parent_gui and self.hop_count != pck['hop_count'] + 1:  # if parent's hop count is changed
            self.hop_count = pck['hop_count'] + 1
            self.send_heart_beat()
        for member in self.members_table:
            for neighbor in self.neighbors_table:
                if member == neighbor:
                    if self.neighbors_table[neighbor]["parent_gui"] != self.id:
                        self.members_table.remove(member)
                    elif self.neighbors_table[neighbor]["parent_gui"] == self.id and neighbor not in self.members_table:
                        pass
        for neighbor in self.neighbors_table:
            if self.neighbors_table[neighbor]["parent_gui"] == self.id and neighbor not in self.members_table:
                self.members_table.append(neighbor)
        self.set_colors()

    ###################
    def check_neighbors(self):
        """Checks neighbors if they are still alive or not. If not, updates necessary tables.
        Sends heartbeat and network update messages in need.

        Args:

        Returns:

        """
        childs_updated = False
        parent_dead = False
        will_be_removed = []
        for gui, pck in self.neighbors_table.items():
            if self.now - pck['arrival_time'] > 3 * config.HEARTH_BEAT_TIME_INTERVAL:
                will_be_removed.append(gui)
                if gui == self.parent_gui:
                    parent_dead = True
                if gui in self.child_networks_table.keys():
                    del self.child_networks_table[gui]
                    childs_updated = True
                if gui in self.candidate_parents_table:
                    self.candidate_parents_table.remove(gui)
        for gui in will_be_removed:
            del self.neighbors_table[gui]
        if self.role != Roles.UNREGISTERED:
            if parent_dead:
                self.repair()
            else:
                self.send_heart_beat()
                self.set_timer('TIMER_HEART_BEAT', config.HEARTH_BEAT_TIME_INTERVAL)
                if childs_updated:
                    if self.role != Roles.ROOT and self.parent_gui is not None:
                        self.send_network_update()

    ###################
    def select_and_join(self):
        """Chooses the node with minimum hop count to the root (on tie, minimum gui) and send a join request message.
           Additionally, it tries to make the network self-optimized by choosing minimum hop parents for unregistered nodes based on multiple simulations.
           Optimization: selects minimum hop node, priority is a root node, then a clusterhead and lastly, a registered node.
        Args:

        Returns:

        """
        min_hop = 99999
        min_hop_gui = 99999

        # for member_gui in self.members_table:
        #     if member_gui == self.neighbors_table[min_hop_gui]['gui']:
        #         print('got you', self.id, self.neighbors_table[min_hop_gui]['gui'], member_gui,
        #               self.candidate_parents_table)
        #         self.candidate_parents_table.remove(gui)
        #         print('go away', self.id, self.neighbors_table[min_hop_gui]['gui'], member_gui,
        #               self.candidate_parents_table)

        for gui in self.candidate_parents_table:
            if self.neighbors_table[gui]['hop_count'] < min_hop or (self.neighbors_table[gui]['hop_count'] == min_hop and gui < min_hop_gui):
                min_hop = self.neighbors_table[gui]['hop_count']
                if self.neighbors_table[gui]['gui'] not in self.members_table:
                    min_hop_gui = gui
        for gui in self.candidate_parents_table:
            if self.neighbors_table[gui]['role'] == Roles.ROOT:
                min_hop = self.neighbors_table[gui]['hop_count']
                if self.neighbors_table[gui]['gui'] not in self.members_table:
                    min_hop_gui = gui
                break
            elif self.neighbors_table[gui]['role'] == Roles.CLUSTER_HEAD:
                if self.neighbors_table[gui]['hop_count'] < min_hop or (self.neighbors_table[min_hop_gui]['role'] == Roles.REGISTERED and self.neighbors_table[gui]['hop_count'] < min_hop + 2):
                    min_hop = self.neighbors_table[gui]['hop_count']
                    if self.neighbors_table[gui]['gui'] not in self.members_table:
                        min_hop_gui = gui
            else:
                if self.neighbors_table[gui]['hop_count'] < min_hop:
                    if self.neighbors_table[min_hop_gui]['role'] == Roles.CLUSTER_HEAD:
                        if self.neighbors_table[gui]['hop_count'] < min_hop - 2:
                            min_hop = self.neighbors_table[gui]['hop_count']
                            if self.neighbors_table[gui]['gui'] not in self.members_table:
                                min_hop_gui = gui
                    elif self.neighbors_table[min_hop_gui]['role'] == Roles.REGISTERED:
                        min_hop = self.neighbors_table[gui]['hop_count']
                        if self.neighbors_table[gui]['gui'] not in self.members_table:
                            min_hop_gui = gui
        selected_addr = self.neighbors_table[min_hop_gui]['source']
        self.send_join_request(selected_addr)
        self.set_timer('TIMER_JOIN_REQUEST', 5)

    ###################
    def repair(self):
        """Executes chosen repairing instructions.

        Args:

        Returns:

        """
        if self.role == Roles.REGISTERED:
            self.become_unregistered()
        else:
            if config.REPAIRING_METHOD == 'ALL_ORPHAN':
                self.repair_all_orphan()
            elif config.REPAIRING_METHOD == 'FIND_ANOTHER_PARENT':
                self.repair_find_another_parent()

    ###################
    def repair_all_orphan(self):
        """Becomes unregistered and sends I am orphan message.

        Args:

        Returns:

        """
        self.send_i_am_orphan()
        self.become_unregistered()

    ###################
    def repair_find_another_parent(self):
        """If it has potential parent in its table, tries to connect any of them. Otherwise, becomes unregistered.

        Args:

        Returns:

        """
        if self.parent_gui in self.candidate_parents_table:
            self.candidate_parents_table.remove(self.parent_gui)
            del self.neighbors_table[self.parent_gui]
        if len(self.candidate_parents_table) != 0:
            self.kill_all_timers()
            self.erase_parent()
            self.role = Roles.UNREGISTERED
            self.select_and_join()
        else:
            self.send_i_am_orphan()
            self.become_unregistered()

    ###################
    def route_and_forward_package(self, pck):
        """Routes and forwards given package

        Args:
            pck (Dict): package to route and forward it should contain dest, source and type.
        Returns:

        """

        if self.parent_gui is None:
            pass
        if self.role != Roles.ROOT and self.parent_gui is not None:
            pck['next_hop'] = self.neighbors_table[self.parent_gui]['addr']
        if self.ch_addr is not None:
            if pck['dest'].net_addr == self.ch_addr.net_addr:
                pck['next_hop'] = pck['dest']
            else:
                for child_gui, child_networks in self.child_networks_table.items():
                    if pck['dest'].net_addr in child_networks:
                        pck['next_hop'] = self.neighbors_table[child_gui]['addr']
        elif len(self.child_networks_table) != 0:
            for child_gui, child_networks in self.child_networks_table.items():
                if pck['dest'].net_addr in child_networks:
                    pck['next_hop'] = self.neighbors_table[child_gui]['addr']
        self.send(pck)

    ##################
    def send_i_am_orphan(self):
        """Sends i am orphan message to inform its neighbors.

        Args:

        Returns:

        """
        self.send({'dest': wsn.BROADCAST_ADDR,
                   'type': 'I_AM_ORPHAN',
                   'source': self.addr,
                   'gui':self.id})

    ###################
    def send_probe(self):
        """Sends probe message to be discovered and registered.

        Args:

        Returns:

        """
        self.send({'dest': wsn.BROADCAST_ADDR,
                   'type': 'PROBE',
                   'source': self.addr,
                   'gui': self.id})

    ###################
    def send_heart_beat(self):
        """Sends heart beat message

        Args:

        Returns:

        """
        self.send({'dest': wsn.BROADCAST_ADDR,
                   'type': 'HEART_BEAT',
                   'source': self.ch_addr if self.ch_addr is not None else self.addr,
                   'gui': self.id,
                   'role': self.role,
                   'addr': self.addr,
                   'ch_addr': self.ch_addr,
                   'hop_count': self.hop_count,
                   'parent_gui': self.parent_gui})

    ###################
    def send_join_request(self, dest):
        """Sends join request message to given destination address to join destination network

        Args:
            dest (Addr): Address of destination node
        Returns:

        """
        self.send({'dest': dest,
                   'type': 'JOIN_REQUEST',
                   'source': self.addr,
                   'gui': self.id,
                   'ch_addr': self.ch_addr})

    ###################
    def send_join_reply(self, gui, addr):
        """Sends join reply message to register the node requested to join.
        The message includes a gui to determine which node will take this reply, an addr to be assigned to the node
        and a root_addr.

        Args:
            gui (int): Global unique ID
            addr (Addr): Address that will be assigned to new registered node
        Returns:

        """
        self.send({'dest': wsn.BROADCAST_ADDR,
                   'type': 'JOIN_REPLY',
                   'source': self.ch_addr if self.ch_addr is not None else self.addr,
                   'gui': self.id,
                   'dest_gui': gui,
                   'addr': addr,
                   'root_addr': self.root_addr,
                   'hop_count': self.hop_count + 1})

    ###################
    def send_join_ack(self, dest):
        """Sends join acknowledgement message to given destination address.

        Args:
            dest (Addr): Address of destination node
        Returns:

        """
        self.send({'dest': dest,
                   'type': 'JOIN_ACK',
                   'source': self.addr,
                   'gui': self.id})

    ###################
    def send_network_request(self, gui):
        """Sends network request message to root address to be cluster head

        Args:

        Returns:

        """
        self.route_and_forward_package({'dest': self.root_addr,
                                        'type': 'NETWORK_REQUEST',
                                        'source': self.addr,
                                        'gui': gui})

    ###################
    def send_network_reply(self, dest, addr, gui):
        """Sends network reply message to dest address

        Args:
            dest (Addr): destination address
            addr (Addr): cluster head address of new network

        Returns:

        """
        self.route_and_forward_package({'dest': dest,
                                        'type': 'NETWORK_REPLY',
                                        'source': self.addr,
                                        'addr': addr,
                                        'gui': gui})

    ###################
    def send_network_update(self):
        """Sends network update message to parent

        Args:

        Returns:

        """
        if self.role == Roles.CLUSTER_HEAD:
            child_networks = [self.ch_addr.net_addr]
        else:
            child_networks = [self.id]
        for networks in self.child_networks_table.values():
            child_networks.extend(networks)
        if self.parent_gui is not None and (self.parent_gui in self.neighbors_table):
            self.send({'dest': self.neighbors_table[self.parent_gui]['addr'],
                       'type': 'NETWORK_UPDATE',
                       'source': self.addr,
                       'gui': self.id,
                       'child_networks': child_networks})
        else:
            pass

    ###################
    def send_clusterhead_transfer(self, gui):
        """Sending clusterhead transfer message to gui to become cluster head
        Args:
            gui
        Returns:

        """
        self.send({'dest': self.neighbors_table[gui]['addr'],
                   'type': 'CLUSTERHEAD_TRANSFER',
                   'source': self.addr,
                   'gui': self.id,
                   'ch_addr': self.ch_addr})

    ###################
    def send_clusterhead_ack(self, dest):
        """Sending clusterhead acknowledgement message to the destination address
           so that the role of the destination will become registered, and it will function as a router between two clusters

        Args:
            dest (Addr): Address of destination node
        Returns:

        """
        self.send({'dest': dest,
                   'type': 'CLUSTERHEAD_ACK',
                   'source': self.addr,
                   'gui': self.id})

    ###################
    def multicast_subscribe(self):
        """Subscriber will listen to multicast packet

        Args:

        Returns:

        """
        self.send({'dest': wsn.BROADCAST_ADDR,
                   'type': 'MULTICAST_SUBSCRIBE',
                   'multicast_subscriber': self.addr,
                   'gui': self.id})

    ###################
    def on_receive(self, pck):
        """Executes when a package received.

        Args:
            pck (Dict): received package
        Returns:

        """
        # ROOT or CLUSTERHEAD
        if self.role == Roles.ROOT or self.role == Roles.CLUSTER_HEAD:  # if the node is root or cluster head
            if 'next_hop' in pck.keys() and pck['dest'] != self.addr and pck['dest'] != self.ch_addr:  # forwards message if destination is not itself
                self.route_and_forward_package(pck)
                return
            if pck['type'] == 'HEART_BEAT':  # updates neighbor information and relations
                self.update_neighbor(pck)
            if pck['type'] == 'PROBE':  # it sends heart beat message
                self.send_heart_beat()
            if pck['type'] == 'JOIN_REQUEST':  # it and sends join reply message once received join request
                self.send_join_reply(pck['gui'], wsn.Addr(self.ch_addr.net_addr, pck['gui']))
            if pck['type'] == 'NETWORK_REQUEST':  # it sends a network reply to requested node
                if self.role == Roles.ROOT:
                    new_addr = wsn.Addr(pck['gui'], 254)
                    self.send_network_reply(pck['source'], new_addr, pck['gui'])
            if pck['type'] == 'JOIN_ACK':  # updates members table
                self.members_table.append(pck['gui'])
            if pck['type'] == 'NETWORK_UPDATE':  # updates child networks table and sends network update message
                self.child_networks_table[pck['gui']] = pck['child_networks']
                if self.role != Roles.ROOT:
                    if self.parent_gui is not None:
                        self.send_network_update()
                    else:
                        pass
            if pck['type'] == 'I_AM_ORPHAN':  # if the sender is parent, starts repairing procedure
                if pck['gui'] == self.parent_gui:
                    self.candidate_parents_table.remove(self.parent_gui)
                    del self.neighbors_table[self.parent_gui]
                    self.erase_parent()
                    self.parent_gui = None
                    self.repair()
            if pck['type'] == 'SENSOR':
                pass
                # self.log(str(pck['source']) + '--' + str(pck['sensor_value']))
            if pck['type'] == 'NETWORK_REPLY':  # it becomes cluster head and send join reply to the candidates
                if pck['dest'] == self.addr:
                    self.role = Roles.CLUSTER_HEAD
                    self.scene.nodecolor(self.id, 0, 0, 1)
                    self.ch_addr = pck['addr']
                    self.send_network_update()
                    self.send_heart_beat()
                    gui = self.received_JR_guis
                    self.send_join_reply(gui, wsn.Addr(self.ch_addr.net_addr, gui))
                    self.set_timer("TIMER_CLUSTERHEAD_TRANSFER", 1)
            if pck['type'] == 'JOIN_REPLY':
                if pck['dest_gui'] == self.id:
                    self.erase_parent()
                    self.parent_gui = pck['gui']
                    self.hop_count = pck['hop_count']
                    self.draw_parent()
                    self.send_network_update()
                    self.send_join_ack(pck['source'])
                    self.set_timer('TIMER_HEART_BEAT', config.HEARTH_BEAT_TIME_INTERVAL)
                    if self.isSubscriber == True:
                        self.set_timer('TIMER_MULTICAST_SUBSCRIBE', 50)
            if pck['type'] == 'CLUSTERHEAD_ACK': # acknowledges that it is no longer a clusterhead
                self.role = Roles.REGISTERED
                self.scene.nodecolor(self.id, 1, 0, 1)
                self.ch_addr = None
                if self.parent_gui is not None:
                    self.send_network_update()
                self.send_heart_beat()
            if pck ['type'] == 'MULTICAST_SUBSCRIBE':
                if self.role == Roles.ROOT:
                    print('I,', self.id, ', am broadcasting')
                if pck['gui'] in self.members_table:
                    print('I,', self.id, ', found a multicast channel')
                    self.multicast_channel_IDs.append(pck['multicast_subscriber'])
                    print('source:', pck['multicast_subscriber'])
                    self.multicast_subscribe()
                else:
                    pass
        # REGISTERED
        elif self.role == Roles.REGISTERED:  # if the node is registered
            if 'next_hop' in pck.keys() and pck['dest'] != self.addr:  # forwards message if destination is not itself
                self.route_and_forward_package(pck)
                return
            if pck['type'] == 'HEART_BEAT':  # updates neighbor information and relations
                self.update_neighbor(pck)
            if pck['type'] == 'PROBE':  # it sends heart beat message
                self.send_heart_beat()
            if pck['type'] == 'JOIN_REQUEST':  # it sends a network request to the root
                if pck['dest'] == self.addr:
                    if pck['ch_addr'] is not None:
                        self.send_join_reply(pck['gui'], pck['ch_addr'])
                        self.scene.nodecolor(self.id, 1, 0, 1)
                        self.send_network_update()
                    else:
                        self.received_JR_guis = pck['gui']
                        self.send_network_request(pck['gui'])
            if pck['type'] == 'JOIN_ACK':  # updates members table
                self.members_table.append(pck['gui'])
                self.send_network_update()
            if pck['type'] == 'NETWORK_REPLY':  # it becomes cluster head and send join reply to the candidates
                if pck['dest'] == self.addr:
                    self.role = Roles.CLUSTER_HEAD
                    self.scene.nodecolor(self.id, 0, 0, 1)
                    self.ch_addr = pck['addr']
                    self.send_network_update()
                    self.send_heart_beat()
                    gui = self.received_JR_guis
                    self.send_join_reply(gui, wsn.Addr(self.ch_addr.net_addr, gui))
                    self.set_timer("TIMER_CLUSTERHEAD_TRANSFER", 1)
            if pck['type'] == 'JOIN_REPLY':
                if pck['dest_gui'] == self.id:
                    self.erase_parent()
                    self.addr = pck['addr']
                    self.parent_gui = pck['gui']
                    self.hop_count = pck['hop_count']
                    self.draw_parent()
                    self.kill_timer('TIMER_JOIN_REQUEST')
                    self.send_heart_beat()
                    self.set_timer('TIMER_HEART_BEAT', config.HEARTH_BEAT_TIME_INTERVAL)
                    self.send_join_ack(pck['source'])
                    if self.isSubscriber == True:
                        self.set_timer('TIMER_MULTICAST_SUBSCRIBE', 50)
            if pck['type'] == 'I_AM_ORPHAN':  # if the sender is parent, starts repairing procedure
                if pck['gui'] == self.parent_gui:
                    self.candidate_parents_table.remove(self.parent_gui)
                    del self.neighbors_table[self.parent_gui]
                    self.erase_parent()
                    self.parent_gui = None
                    self.repair()
            if pck['type'] == 'CLUSTERHEAD_TRANSFER':  # receives this message and becomes a clusterhead
                if pck['dest'] == self.addr:
                    self.role = Roles.CLUSTER_HEAD
                    self.scene.nodecolor(self.id, 0, 0, 1)
                    self.addr = pck['ch_addr']
                    self.ch_addr = pck['ch_addr']
                    if self.parent_gui is not None:
                        self.send_network_update()
                    self.send_heart_beat()
                    self.send_clusterhead_ack(pck['source'])
            if pck['type'] == 'NETWORK_UPDATE':  # updates child networks table and sends network update message
                self.child_networks_table[pck['gui']] = pck['child_networks']
                self.send_network_update()
            if pck ['type'] == 'MULTICAST_SUBSCRIBE':
                if pck['gui'] in self.members_table:
                    print('I,', self.id, ', found a multicast channel')
                    self.multicast_channel_IDs.append(pck['multicast_subscriber'])
                    print('source:', pck['multicast_subscriber'])
                    self.multicast_subscribe()
        # UNDISCOVERED
        elif self.role == Roles.UNDISCOVERED:  # if the node is undiscovered
            if pck['type'] == 'HEART_BEAT':  # it kills probe timer, becomes unregistered and sets join request timer
                self.update_neighbor(pck)
                self.kill_timer('TIMER_PROBE')
                self.become_unregistered()
        # UNREGISTERED
        if self.role == Roles.UNREGISTERED:  # if the node is unregistered
            if pck['type'] == 'HEART_BEAT':
                self.update_neighbor(pck)
            if pck['type'] == 'JOIN_REPLY':  # becomes registered and sends join ack if the message is sent to itself
                if pck['dest_gui'] == self.id:
                    self.addr = pck['addr']
                    self.parent_gui = pck['gui']
                    self.root_addr = pck['root_addr']
                    self.hop_count = pck['hop_count']
                    self.draw_parent()
                    self.kill_timer('TIMER_JOIN_REQUEST')
                    self.send_heart_beat()
                    self.set_timer('TIMER_HEART_BEAT', config.HEARTH_BEAT_TIME_INTERVAL)
                    self.send_join_ack(pck['source'])
                    if self.ch_addr is not None:  # if it is in repairing phase
                        self.role = Roles.CLUSTER_HEAD
                        self.send_network_update()
                    else:
                        self.role = Roles.REGISTERED
                        self.scene.nodecolor(self.id, 0, 1, 0)
                    if self.isSubscriber == True:
                        self.set_timer('TIMER_MULTICAST_SUBSCRIBE', 50)
                    # sensor implementation
                    timer_duration = self.id % 20
                    if timer_duration == 0: timer_duration = 1
                    self.set_timer('TIMER_SENSOR', timer_duration)

    ###################
    def on_timer_fired(self, name, *args, **kwargs):
        """Executes when a timer fired.

        Args:
            name (string): Name of timer.
            *args (string): Additional args.
            **kwargs (string): Additional key word args.
        Returns:

        """
        self.set_colors()
        if name == 'TIMER_ARRIVAL':  # it wakes up and set timer probe once time arrival timer fired
            self.scene.nodecolor(self.id, 1, 0, 0)  # sets self color to red
            self.wake_up()
            self.set_timer('TIMER_PROBE', 1)
        elif name == 'TIMER_PROBE':  # it sends probe if counter didn't reach the threshold once timer probe fired.
            if self.c_probe < self.th_probe:
                self.send_probe()
                self.c_probe += 1
                self.set_timer('TIMER_PROBE', 1)
            else:  # if the counter reached the threshold
                if self.is_root_eligible:  # if the node is root eligible, it becomes root
                    self.role = Roles.ROOT
                    self.scene.nodecolor(self.id, 0, 0, 0)
                    self.addr = wsn.Addr(self.id, 254)
                    self.ch_addr = wsn.Addr(self.id, 254)
                    self.root_addr = self.addr
                    self.hop_count = 0
                    self.set_timer('TIMER_HEART_BEAT', config.HEARTH_BEAT_TIME_INTERVAL)
                else:  # otherwise it keeps trying to sends probe after a long time
                    self.c_probe = 0
                    self.set_timer('TIMER_PROBE', 30)
        elif name == 'TIMER_HEART_BEAT':  # it sends heart beat message once heart beat timer fired
            self.check_neighbors()
        elif name == 'TIMER_JOIN_REQUEST':  # if it has not received heart beat messages before, it sets timer again and wait heart beat messages once join request timer fired.
            self.check_neighbors()
            if len(self.candidate_parents_table) == 0:
                    self.send_i_am_orphan()
                    self.become_unregistered()
            else:  # otherwise it chose one of them and sends join request
                self.select_and_join()
        elif name == 'TIMER_SENSOR':
            self.route_and_forward_package({'dest': self.root_addr, 'type': 'SENSOR', 'source': self.addr, 'sensor_value': random.uniform(10, 50)})
            timer_duration = self.id % 20
            if timer_duration == 0: timer_duration = 1
            self.set_timer('TIMER_SENSOR', timer_duration)
        elif name == 'TIMER_DEAD':  # it dies and goes to sleep
            self.scene.nodecolor(self.id, 1, 0, 0)  # sets self color to red
            self.erase_parent()
            self.sleep()
            self.kill_all_timers()
            self.scene.nodecolor(self.id, 1, 0, 0)
            self.set_timer('TIMER_WAKE_UP', 20)
        elif name == 'TIMER_WAKE_UP':
            self.wake_up()
            self.child_networks_table = {}
            if self.parent_gui is not None:
                self.send_network_update()
            self.addr = None
            self.ch_addr = None
            self.parent_gui = None
            self.root_addr = None
            self.role = Roles.UNREGISTERED
            self.c_probe = 0
            self.th_probe = 10
            self.hop_count = 99999
            self.neighbors_table = {}
            self.candidate_parents_table = []
            self.child_networks_table = {}
            self.members_table = []
            self.send_probe()
            self.set_timer('TIMER_JOIN_REQUEST', 20)
        elif name == 'TIMER_CLUSTERHEAD_TRANSFER':  # it dies and goes to sleep
            gui = self.received_JR_guis
            self.send_clusterhead_transfer(gui)
        elif name == 'TIMER_MULTICAST_SUBSCRIBE':
            if wsn.Addr(254, 2) in self.multicast_channel_IDs:
                pass
            else:
                self.multicast_channel_IDs.append(wsn.Addr(254, 2))
                self.scene.nodecolor(self.id, 1, 0, 0)
                self.multicast_subscribe()
                self.set_timer('TIMER_MULTICAST_SUBSCRIBE', 50)


ROOT_ID = random.randint(0, config.SIM_NODE_COUNT)


###########################################################
def create_network(node_class, number_of_nodes = 100):
    """Creates given number of nodes at random positions with random arrival times.

    Args:
        node_class (Class): Node class to be created.
        number_of_nodes (int): Number of nodes.
    Returns:

    """
    edge = math.ceil(math.sqrt(number_of_nodes))
    for i in range(number_of_nodes):
        x = i / edge
        y = i % edge
        px = 50 + x * config.SIM_NODE_PLACING_CELL_SIZE + random.uniform(-1 * config.SIM_NODE_PLACING_CELL_SIZE / 3,
                                                                         config.SIM_NODE_PLACING_CELL_SIZE / 3)
        py = 50 + y * config.SIM_NODE_PLACING_CELL_SIZE + random.uniform(-1 * config.SIM_NODE_PLACING_CELL_SIZE / 3,
                                                                         config.SIM_NODE_PLACING_CELL_SIZE / 3)
        node = sim.add_node(node_class, (px, py))
        node.tx_range = config.NODE_TX_RANGE
        node.logging = True
        node.arrival = random.uniform(0, config.NODE_ARRIVAL_MAX)
        if node.id == ROOT_ID:
            node.arrival = 0.1


sim = wsn.Simulator(duration=config.SIM_DURATION,
                    timescale=config.SIM_TIME_SCALE,
                    visual=config.SIM_VISUALIZATION,
                    terrain_size=config.SIM_TERRAIN_SIZE,
                    title=config.SIM_TITLE)

# creating random network
create_network(SensorNode, config.SIM_NODE_COUNT)

# start the simulation
sim.run()

# Sleeping or dead nodes are white
# Activated and undiscovered nodes are red
# Discovered and unregistered nodes are yellow
# Registered nodes are green
# Root node is black
# Cluster Heads are blue
# Routers are purple
# Multicast listeners are red
# Multicast publisher is light blue
