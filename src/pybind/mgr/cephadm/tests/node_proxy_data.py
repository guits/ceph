full_set_with_critical = {
  "host": "host01",
  "sn": "12345",
  "status": {
    "storage": {
      "disk.bay.0:enclosure.internal.0-1:raid.integrated.1-1": {
        "description": "Solid State Disk 0:1:0",
        "entity": "RAID.Integrated.1-1",
        "capacity_bytes": 959656755200,
        "model": "KPM5XVUG960G",
        "protocol": "SAS",
        "serial_number": "8080A1CRTP5F",
        "status": {
          "health": "Critical",
          "healthrollup": "OK",
          "state": "Enabled"
        },
        "physical_location": {
          "partlocation": {
            "locationordinalvalue": 0,
            "locationtype": "Slot"
          }
        }
      },
      "disk.bay.9:enclosure.internal.0-1": {
        "description": "PCIe SSD in Slot 9 in Bay 1",
        "entity": "CPU.1",
        "capacity_bytes": 1600321314816,
        "model": "Dell Express Flash NVMe P4610 1.6TB SFF",
        "protocol": "PCIe",
        "serial_number": "PHLN035305MN1P6AGN",
        "status": {
          "health": "Critical",
          "healthrollup": "OK",
          "state": "Enabled"
        },
        "physical_location": {
          "partlocation": {
            "locationordinalvalue": 9,
            "locationtype": "Slot"
          }
        }
      }
    },
    "processors": {
      "cpu.socket.2": {
        "description": "Represents the properties of a Processor attached to this System",
        "total_cores": 20,
        "total_threads": 40,
        "processor_type": "CPU",
        "model": "Intel(R) Xeon(R) Gold 6230 CPU @ 2.10GHz",
        "status": {
          "health": "OK",
          "state": "Enabled"
        },
        "manufacturer": "Intel"
      },
      
    },
    "network": {
      "nic.slot.1-1-1": {
        "description": "NIC in Slot 1 Port 1 Partition 1",
        "name": "System Ethernet Interface",
        "speed_mbps": 0,
        "status": {
          "health": "OK",
          "state": "StandbyOffline"
        }
      }
    },
    "memory": {
      "dimm.socket.a1": {
        "description": "DIMM A1",
        "memory_device_type": "DDR4",
        "capacity_mi_b": 31237,
        "status": {
          "health": "Critical",
          "state": "Enabled"
        }
      }
    }
  },
  "firmwares": {
    
  }
}

mgr_inventory_cache = {"host01": {"hostname": "host01",
                                  "addr": "10.10.10.11",
                                  "labels": ["_admin"],
                                  "status": "",
                                  "idrac": {"hostname": "10.10.10.11",
                                            "username": "root",
                                            "password": "ceph123"}},
                       "host02": {"hostname": "host02",
                                  "addr": "10.10.10.12",
                                  "labels": [],
                                  "status": "",
                                  "idrac": {"hostname": "10.10.10.12",
                                            "username": "root",
                                            "password": "ceph123"}}}

full_set = {
  "host01": {
    "host": "host01",
    "sn": "FR8Y5X3",
    "status": {
      "storage": {
        "disk.bay.8:enclosure.internal.0-1:nonraid.slot.2-1": {
          "description": "Disk 8 in Backplane 1 of Storage Controller in Slot 2",
          "entity": "NonRAID.Slot.2-1",
          "capacity_bytes": 20000588955136,
          "model": "ST20000NM008D-3D",
          "protocol": "SATA",
          "serial_number": "ZVT99QLL",
          "status": {
            "health": "OK",
            "healthrollup": "OK",
            "state": "Enabled"
          },
          "physical_location": {
            "partlocation": {
              "locationordinalvalue": 8,
              "locationtype": "Slot"
            }
          }
        }
      },
      "processors": {
        "cpu.socket.2": {
          "description": "Represents the properties of a Processor attached to this System",
          "total_cores": 16,
          "total_threads": 32,
          "processor_type": "CPU",
          "model": "Intel(R) Xeon(R) Silver 4314 CPU @ 2.40GHz",
          "status": {
            "health": "OK",
            "state": "Enabled"
          },
          "manufacturer": "Intel"
        },
        "cpu.socket.1": {
          "description": "Represents the properties of a Processor attached to this System",
          "total_cores": 16,
          "total_threads": 32,
          "processor_type": "CPU",
          "model": "Intel(R) Xeon(R) Silver 4314 CPU @ 2.40GHz",
          "status": {
            "health": "OK",
            "state": "Enabled"
          },
          "manufacturer": "Intel"
        }
      },
      "network": {
        "oslogicalnetwork.2": {
          "description": "eno8303",
          "name": "eno8303",
          "speed_mbps": 0,
          "status": {
            "health": "OK",
            "state": "Enabled"
          }
        }
      },
      "memory": {
        "dimm.socket.a1": {
          "description": "DIMM A1",
          "memory_device_type": "DDR4",
          "capacity_mi_b": 16384,
          "status": {
            "health": "OK",
            "state": "Enabled"
          }
        }
      },
      "power": {
        "0": {
          "name": "PS1 Status",
          "model": "PWR SPLY,800W,RDNT,LTON",
          "manufacturer": "DELL",
          "status": {
            "health": "OK",
            "state": "Enabled"
          }
        },
        "1": {
          "name": "PS2 Status",
          "model": "PWR SPLY,800W,RDNT,LTON",
          "manufacturer": "DELL",
          "status": {
            "health": "OK",
            "state": "Enabled"
          }
        }
      },
      "fans": {
        "0": {
          "name": "System Board Fan1A",
          "physical_context": "SystemBoard",
          "status": {
            "health": "OK",
            "state": "Enabled"
          }
        }
      }
    },
    "firmwares": {
      "installed-28897-6.10.30.20__usc.embedded.1:lc.embedded.1": {
        "name": "Lifecycle Controller",
        "description": "Represents Firmware Inventory",
        "release_date": "00:00:00Z",
        "version": "6.10.30.20",
        "updateable": True,
        "status": {
          "health": "OK",
          "state": "Enabled"
        }
      }
    }
  },
"host02": {
    "host": "host02",
    "sn": "FR8Y5X4",
    "status": {
      "storage": {
        "disk.bay.8:enclosure.internal.0-1:nonraid.slot.2-1": {
          "description": "Disk 8 in Backplane 1 of Storage Controller in Slot 2",
          "entity": "NonRAID.Slot.2-1",
          "capacity_bytes": 20000588955136,
          "model": "ST20000NM008D-3D",
          "protocol": "SATA",
          "serial_number": "ZVT99QLL",
          "status": {
            "health": "OK",
            "healthrollup": "OK",
            "state": "Enabled"
          },
          "physical_location": {
            "partlocation": {
              "locationordinalvalue": 8,
              "locationtype": "Slot"
            }
          }
        }
      },
      "processors": {
        "cpu.socket.2": {
          "description": "Represents the properties of a Processor attached to this System",
          "total_cores": 16,
          "total_threads": 32,
          "processor_type": "CPU",
          "model": "Intel(R) Xeon(R) Silver 4314 CPU @ 2.40GHz",
          "status": {
            "health": "OK",
            "state": "Enabled"
          },
          "manufacturer": "Intel"
        },
        "cpu.socket.1": {
          "description": "Represents the properties of a Processor attached to this System",
          "total_cores": 16,
          "total_threads": 32,
          "processor_type": "CPU",
          "model": "Intel(R) Xeon(R) Silver 4314 CPU @ 2.40GHz",
          "status": {
            "health": "OK",
            "state": "Enabled"
          },
          "manufacturer": "Intel"
        }
      },
      "network": {
        "oslogicalnetwork.2": {
          "description": "eno8303",
          "name": "eno8303",
          "speed_mbps": 0,
          "status": {
            "health": "OK",
            "state": "Enabled"
          }
        }
      },
      "memory": {
        "dimm.socket.a1": {
          "description": "DIMM A1",
          "memory_device_type": "DDR4",
          "capacity_mi_b": 16384,
          "status": {
            "health": "OK",
            "state": "Enabled"
          }
        }
      },
      "power": {
        "0": {
          "name": "PS1 Status",
          "model": "PWR SPLY,800W,RDNT,LTON",
          "manufacturer": "DELL",
          "status": {
            "health": "OK",
            "state": "Enabled"
          }
        },
        "1": {
          "name": "PS2 Status",
          "model": "PWR SPLY,800W,RDNT,LTON",
          "manufacturer": "DELL",
          "status": {
            "health": "OK",
            "state": "Enabled"
          }
        }
      },
      "fans": {
        "0": {
          "name": "System Board Fan1A",
          "physical_context": "SystemBoard",
          "status": {
            "health": "OK",
            "state": "Enabled"
          }
        }
      }
    },
    "firmwares": {
      "installed-28897-6.10.30.20__usc.embedded.1:lc.embedded.1": {
        "name": "Lifecycle Controller",
        "description": "Represents Firmware Inventory",
        "release_date": "00:00:00Z",
        "version": "6.10.30.20",
        "updateable": True,
        "status": {
          "health": "OK",
          "state": "Enabled"
        }
      }
    }
  }
}