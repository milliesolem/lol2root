## catalog.nim - assembles every check module into one registry.

import core
import checks/system
import checks/files
import checks/services
import checks/network
import checks/kernel
import checks/protections
import checks/software
import checks/container
import checks/interesting

proc buildRegistry*(): Registry =
  result = Registry()
  system.register(result)
  files.register(result)
  services.register(result)
  network.register(result)
  kernel.register(result)
  protections.register(result)
  software.register(result)
  container.register(result)
  interesting.register(result)
