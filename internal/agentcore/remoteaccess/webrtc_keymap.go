package remoteaccess

import (
	"strings"
)

var domCodeLinuxInputCodes = map[string]int{
	"Escape": 1,
	"Digit1": 2, "Digit2": 3, "Digit3": 4, "Digit4": 5, "Digit5": 6,
	"Digit6": 7, "Digit7": 8, "Digit8": 9, "Digit9": 10, "Digit0": 11,
	"Minus": 12, "Equal": 13, "Backspace": 14, "Tab": 15,
	"KeyQ": 16, "KeyW": 17, "KeyE": 18, "KeyR": 19, "KeyT": 20,
	"KeyY": 21, "KeyU": 22, "KeyI": 23, "KeyO": 24, "KeyP": 25,
	"BracketLeft": 26, "BracketRight": 27, "Enter": 28,
	"ControlLeft": 29,
	"KeyA":        30, "KeyS": 31, "KeyD": 32, "KeyF": 33, "KeyG": 34,
	"KeyH": 35, "KeyJ": 36, "KeyK": 37, "KeyL": 38,
	"Semicolon": 39, "Quote": 40, "Backquote": 41,
	"ShiftLeft": 42, "Backslash": 43,
	"KeyZ": 44, "KeyX": 45, "KeyC": 46, "KeyV": 47, "KeyB": 48,
	"KeyN": 49, "KeyM": 50, "Comma": 51, "Period": 52, "Slash": 53,
	"ShiftRight": 54, "NumpadMultiply": 55, "AltLeft": 56, "Space": 57,
	"CapsLock": 58,
	"F1":       59, "F2": 60, "F3": 61, "F4": 62, "F5": 63, "F6": 64,
	"F7": 65, "F8": 66, "F9": 67, "F10": 68,
	"NumLock": 69, "ScrollLock": 70,
	"Numpad7": 71, "Numpad8": 72, "Numpad9": 73, "NumpadSubtract": 74,
	"Numpad4": 75, "Numpad5": 76, "Numpad6": 77, "NumpadAdd": 78,
	"Numpad1": 79, "Numpad2": 80, "Numpad3": 81, "Numpad0": 82, "NumpadDecimal": 83,
	"F11": 87, "F12": 88,
	"NumpadEnter": 96, "ControlRight": 97, "NumpadDivide": 98,
	"PrintScreen": 99, "AltRight": 100,
	"Home": 102, "ArrowUp": 103, "PageUp": 104,
	"ArrowLeft": 105, "ArrowRight": 106,
	"End": 107, "ArrowDown": 108, "PageDown": 109,
	"Insert": 110, "Delete": 111,
	"MetaLeft": 125, "MetaRight": 126, "ContextMenu": 127,
}

var domCodeX11Keysyms = map[string]string{
	"Backquote":      "grave",
	"Backslash":      "backslash",
	"Backspace":      "BackSpace",
	"BracketLeft":    "bracketleft",
	"BracketRight":   "bracketright",
	"CapsLock":       "Caps_Lock",
	"Comma":          "comma",
	"ContextMenu":    "Menu",
	"ControlLeft":    "Control_L",
	"ControlRight":   "Control_R",
	"Delete":         "Delete",
	"Digit0":         "0",
	"Digit1":         "1",
	"Digit2":         "2",
	"Digit3":         "3",
	"Digit4":         "4",
	"Digit5":         "5",
	"Digit6":         "6",
	"Digit7":         "7",
	"Digit8":         "8",
	"Digit9":         "9",
	"End":            "End",
	"Enter":          "Return",
	"Equal":          "equal",
	"Escape":         "Escape",
	"F1":             "F1",
	"F10":            "F10",
	"F11":            "F11",
	"F12":            "F12",
	"F2":             "F2",
	"F3":             "F3",
	"F4":             "F4",
	"F5":             "F5",
	"F6":             "F6",
	"F7":             "F7",
	"F8":             "F8",
	"F9":             "F9",
	"Home":           "Home",
	"Insert":         "Insert",
	"KeyA":           "a",
	"KeyB":           "b",
	"KeyC":           "c",
	"KeyD":           "d",
	"KeyE":           "e",
	"KeyF":           "f",
	"KeyG":           "g",
	"KeyH":           "h",
	"KeyI":           "i",
	"KeyJ":           "j",
	"KeyK":           "k",
	"KeyL":           "l",
	"KeyM":           "m",
	"KeyN":           "n",
	"KeyO":           "o",
	"KeyP":           "p",
	"KeyQ":           "q",
	"KeyR":           "r",
	"KeyS":           "s",
	"KeyT":           "t",
	"KeyU":           "u",
	"KeyV":           "v",
	"KeyW":           "w",
	"KeyX":           "x",
	"KeyY":           "y",
	"KeyZ":           "z",
	"MetaLeft":       "Super_L",
	"MetaRight":      "Super_R",
	"Minus":          "minus",
	"NumLock":        "Num_Lock",
	"Numpad0":        "KP_0",
	"Numpad1":        "KP_1",
	"Numpad2":        "KP_2",
	"Numpad3":        "KP_3",
	"Numpad4":        "KP_4",
	"Numpad5":        "KP_5",
	"Numpad6":        "KP_6",
	"Numpad7":        "KP_7",
	"Numpad8":        "KP_8",
	"Numpad9":        "KP_9",
	"NumpadAdd":      "KP_Add",
	"NumpadDecimal":  "KP_Decimal",
	"NumpadDivide":   "KP_Divide",
	"NumpadEnter":    "KP_Enter",
	"NumpadMultiply": "KP_Multiply",
	"NumpadSubtract": "KP_Subtract",
	"PageDown":       "Page_Down",
	"PageUp":         "Page_Up",
	"Period":         "period",
	"PrintScreen":    "Print",
	"Quote":          "apostrophe",
	"ScrollLock":     "Scroll_Lock",
	"Semicolon":      "semicolon",
	"ShiftLeft":      "Shift_L",
	"ShiftRight":     "Shift_R",
	"Slash":          "slash",
	"Space":          "space",
	"Tab":            "Tab",
	"AltLeft":        "Alt_L",
	"AltRight":       "Alt_R",
	"ArrowDown":      "Down",
	"ArrowLeft":      "Left",
	"ArrowRight":     "Right",
	"ArrowUp":        "Up",
}

var domKeyX11Keysyms = map[string]string{
	"Alt":        "Alt_L",
	"Backspace":  "BackSpace",
	"CapsLock":   "Caps_Lock",
	"Control":    "Control_L",
	"Delete":     "Delete",
	"Down":       "Down",
	"End":        "End",
	"Enter":      "Return",
	"Escape":     "Escape",
	"Home":       "Home",
	"Insert":     "Insert",
	"Left":       "Left",
	"Meta":       "Super_L",
	"NumLock":    "Num_Lock",
	"PageDown":   "Page_Down",
	"PageUp":     "Page_Up",
	"Right":      "Right",
	"ScrollLock": "Scroll_Lock",
	"Shift":      "Shift_L",
	"Tab":        "Tab",
	"Up":         "Up",
}

func DomCodeToLinuxInputCode(code string) (int, bool) {
	keyCode, ok := domCodeLinuxInputCodes[strings.TrimSpace(code)]
	return keyCode, ok
}

func DomCodeToX11Keysym(code string) (string, bool) {
	keysym, ok := domCodeX11Keysyms[strings.TrimSpace(code)]
	return keysym, ok
}

func DomKeyToX11Keysym(key string) (string, bool) {
	trimmed := strings.TrimSpace(key)
	if trimmed == "" {
		return "", false
	}
	if keysym, ok := domKeyX11Keysyms[trimmed]; ok {
		return keysym, true
	}
	if len(trimmed) == 1 {
		return strings.ToLower(trimmed), true
	}
	return "", false
}
