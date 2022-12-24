## network properties
BROADCAST_NET_ADDR = 255
BROADCAST_NODE_ADDR = 255

## node properties
NODE_TX_RANGE = 150  # transmission range of nodes
NODE_ARRIVAL_MAX = 200  # max time to wake up

## simulation properties
SIM_NODE_COUNT = 30  # noce count in simulation
SIM_NODE_PLACING_CELL_SIZE = 100  # cell size to place one node
SIM_DURATION = 600  # simulation Duration in seconds
SIM_TIME_SCALE = 0.0001  #  The real time dureation of 1 second simualtion time
SIM_TERRAIN_SIZE = (1400, 600)  #terrain size
SIM_TITLE = 'Data Collection Tree'  # title of visualization window
SIM_VISUALIZATION = True  # visualization active
CANSEND = False
HEARTBEAT_PROBLEM = True

## application properties
HEARTH_BEAT_TIME_INTERVAL = 15
REPAIRING_METHOD = 'FIND_ANOTHER_PARENT' # 'ALL_ORPHAN', 'FIND_ANOTHER_PARENT'