PROGRAM ConveyorInterlock
VAR
    estop_ok : BOOL;
    photoeye : BOOL;
    motor_run : BOOL;
    fault : BOOL;
END_VAR

fault := NOT estop_ok;
motor_run := estop_ok AND photoeye AND NOT fault;
END_PROGRAM
