PROGRAM TankLevel
VAR
    level_high : BOOL;
    level_low : BOOL;
    inlet_valve : BOOL;
    outlet_pump : BOOL;
    alarm : BOOL;
END_VAR

(* Simple tank interlock — additive lab example; does not replace example.st *)
inlet_valve := NOT level_high;
outlet_pump := level_high OR (NOT level_low);
alarm := level_high AND level_low;
END_PROGRAM
