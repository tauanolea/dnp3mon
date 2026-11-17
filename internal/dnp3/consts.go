package dnp3

// Códigos de função da camada de aplicação.
const (
	FCConfirm          = 0
	FCRead             = 1
	FCWrite            = 2
	FCSelect           = 3
	FCOperate          = 4
	FCDirectOperate    = 5
	FCDirectOperateNR  = 6
	FCImmedFreeze      = 7
	FCImmedFreezeNR    = 8
	FCFreezeClear      = 9
	FCFreezeClearNR    = 10
	FCFreezeAtTime     = 11
	FCFreezeAtTimeNR   = 12
	FCColdRestart      = 13
	FCWarmRestart      = 14
	FCInitData         = 15
	FCInitApp          = 16
	FCStartApp         = 17
	FCStopApp          = 18
	FCSaveConfig       = 19
	FCEnableUnsol      = 20
	FCDisableUnsol     = 21
	FCAssignClass      = 22
	FCDelayMeasure     = 23
	FCRecordCurrTime   = 24
	FCOpenFile         = 25
	FCCloseFile        = 26
	FCDeleteFile       = 27
	FCGetFileInfo      = 28
	FCAuthenticateFile = 29
	FCAbortFile        = 30
	FCActivateConfig   = 31
	FCAuthRequest      = 32
	FCAuthRequestNoAck = 33
	FCResponse         = 129
	FCUnsolResponse    = 130
	FCAuthResponse     = 131
)

var fcNames = map[uint8]string{
	0: "CONFIRM", 1: "READ", 2: "WRITE", 3: "SELECT", 4: "OPERATE", 5: "DIRECT_OPERATE",
	6: "DIRECT_OPERATE_NR", 7: "IMMED_FREEZE", 8: "IMMED_FREEZE_NR", 9: "FREEZE_CLEAR",
	10: "FREEZE_CLEAR_NR", 11: "FREEZE_AT_TIME", 12: "FREEZE_AT_TIME_NR", 13: "COLD_RESTART",
	14: "WARM_RESTART", 15: "INITIALIZE_DATA", 16: "INITIALIZE_APPL", 17: "START_APPL",
	18: "STOP_APPL", 19: "SAVE_CONFIG", 20: "ENABLE_UNSOLICITED", 21: "DISABLE_UNSOLICITED",
	22: "ASSIGN_CLASS", 23: "DELAY_MEASURE", 24: "RECORD_CURRENT_TIME", 25: "OPEN_FILE",
	26: "CLOSE_FILE", 27: "DELETE_FILE", 28: "GET_FILE_INFO", 29: "AUTHENTICATE_FILE",
	30: "ABORT_FILE", 31: "ACTIVATE_CONFIG", 32: "AUTHENTICATE_REQ", 33: "AUTH_REQ_NO_ACK",
	129: "RESPONSE", 130: "UNSOLICITED_RESPONSE", 131: "AUTHENTICATE_RESP",
}

// FCName devolve o nome do código de função de aplicação.
func FCName(fc uint8) string {
	if n, ok := fcNames[fc]; ok {
		return n
	}
	return "FC_" + itoa(int(fc))
}

// SensitiveFC indica FCs que alteram o estado da RTU e merecem auditoria.
func SensitiveFC(fc uint8) bool {
	switch fc {
	case FCColdRestart, FCWarmRestart, FCInitData, FCInitApp, FCStartApp, FCStopApp,
		FCSaveConfig, FCDisableUnsol, FCOpenFile, FCDeleteFile, FCActivateConfig, FCAuthenticateFile:
		return true
	}
	return false
}

// Bits de IIN (IIN1 no byte alto, IIN2 no byte baixo).
const (
	IINBroadcast        uint16 = 1 << 8
	IINClass1           uint16 = 1 << 9
	IINClass2           uint16 = 1 << 10
	IINClass3           uint16 = 1 << 11
	IINNeedTime         uint16 = 1 << 12
	IINLocalControl     uint16 = 1 << 13
	IINDeviceTrouble    uint16 = 1 << 14
	IINDeviceRestart    uint16 = 1 << 15
	IINNoFuncSupport    uint16 = 1 << 0
	IINObjectUnknown    uint16 = 1 << 1
	IINParameterError   uint16 = 1 << 2
	IINEventOverflow    uint16 = 1 << 3
	IINAlreadyExec      uint16 = 1 << 4
	IINConfigCorrupt    uint16 = 1 << 5
	IINReserved1        uint16 = 1 << 6
	IINReserved2        uint16 = 1 << 7
	IINEventClassMask          = IINClass1 | IINClass2 | IINClass3 | IINBroadcast
	IINRequestErrorMask        = IINNoFuncSupport | IINObjectUnknown | IINParameterError | IINAlreadyExec
)

// IINBit descreve um bit de IIN.
type IINBit struct {
	Mask     uint16
	Name     string
	Severity string
}

// IINBits lista os bits relevantes, na ordem de exibição.
var IINBits = []IINBit{
	{IINDeviceRestart, "DEVICE_RESTART", "warn"},
	{IINDeviceTrouble, "DEVICE_TROUBLE", "crit"},
	{IINLocalControl, "LOCAL_CONTROL", "warn"},
	{IINNeedTime, "NEED_TIME", "warn"},
	{IINClass3, "CLASS_3_EVENTS", "info"},
	{IINClass2, "CLASS_2_EVENTS", "info"},
	{IINClass1, "CLASS_1_EVENTS", "info"},
	{IINBroadcast, "BROADCAST", "info"},
	{IINConfigCorrupt, "CONFIG_CORRUPT", "crit"},
	{IINAlreadyExec, "ALREADY_EXECUTING", "warn"},
	{IINEventOverflow, "EVENT_BUFFER_OVERFLOW", "crit"},
	{IINParameterError, "PARAMETER_ERROR", "warn"},
	{IINObjectUnknown, "OBJECT_UNKNOWN", "warn"},
	{IINNoFuncSupport, "NO_FUNC_CODE_SUPPORT", "warn"},
	{IINReserved1, "RESERVED_2_6", "info"},
	{IINReserved2, "RESERVED_2_7", "info"},
}

// IINNames devolve os nomes dos bits setados.
func IINNames(iin uint16) []string {
	out := []string{}
	for _, b := range IINBits {
		if iin&b.Mask != 0 {
			out = append(out, b.Name)
		}
	}
	return out
}

// Status de comandos (CROB / saída analógica).
var cmdStatusNames = map[uint8]string{
	0: "SUCCESS", 1: "TIMEOUT", 2: "NO_SELECT", 3: "FORMAT_ERROR", 4: "NOT_SUPPORTED",
	5: "ALREADY_ACTIVE", 6: "HARDWARE_ERROR", 7: "LOCAL", 8: "TOO_MANY_OBJS",
	9: "NOT_AUTHORIZED", 10: "AUTOMATION_INHIBIT", 11: "PROCESSING_LIMITED",
	12: "OUT_OF_RANGE", 13: "DOWNSTREAM_LOCAL", 14: "ALREADY_COMPLETE", 15: "BLOCKED",
	16: "CANCELLED", 17: "BLOCKED_OTHER_MASTER", 18: "DOWNSTREAM_FAIL",
	126: "NON_PARTICIPATING", 127: "UNDEFINED",
}

// CmdStatusName devolve o nome do status de comando.
func CmdStatusName(s uint8) string {
	if n, ok := cmdStatusNames[s]; ok {
		return n
	}
	return "STATUS_" + itoa(int(s))
}

var opTypeNames = []string{"NUL", "PULSE_ON", "PULSE_OFF", "LATCH_ON", "LATCH_OFF"}
var tccNames = []string{"NUL", "CLOSE", "TRIP", "RESERVED"}

// CROBOpName monta um texto como "LATCH_ON" ou "PULSE_ON/TRIP".
func CROBOpName(code uint8) string {
	op := code & 0x0F
	tcc := (code >> 6) & 0x03
	s := "OP_" + itoa(int(op))
	if int(op) < len(opTypeNames) {
		s = opTypeNames[op]
	}
	if tcc != 0 {
		s += "/" + tccNames[tcc]
	}
	if code&0x20 != 0 {
		s += "/CLEAR"
	}
	return s
}

// Flags de qualidade de pontos.
var flagNamesBinary = []string{"ONLINE", "RESTART", "COMM_LOST", "REMOTE_FORCED", "LOCAL_FORCED", "CHATTER_FILTER", "", ""}
var flagNamesAnalog = []string{"ONLINE", "RESTART", "COMM_LOST", "REMOTE_FORCED", "LOCAL_FORCED", "OVER_RANGE", "REFERENCE_ERR", ""}
var flagNamesCounter = []string{"ONLINE", "RESTART", "COMM_LOST", "REMOTE_FORCED", "LOCAL_FORCED", "ROLLOVER", "DISCONTINUITY", ""}

// FlagNames devolve os nomes dos bits de qualidade (exceto o estado).
func FlagNames(typ string, flags uint8) []string {
	var tbl []string
	switch typ {
	case "AI", "FAI", "AOS":
		tbl = flagNamesAnalog
	case "CTR", "FCTR":
		tbl = flagNamesCounter
	default:
		tbl = flagNamesBinary
	}
	out := []string{}
	for i := 0; i < 8; i++ {
		if flags&(1<<i) != 0 && tbl[i] != "" {
			out = append(out, tbl[i])
		}
	}
	return out
}
