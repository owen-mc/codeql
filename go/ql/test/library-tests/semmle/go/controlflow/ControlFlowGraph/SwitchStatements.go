package main

func controller1(msg string) {
	switch {
	case msg == "start":
		start()
	case msg == "stop":
		stop()
	default:
		panic("Message not understood.")
	}
}

func controller2(msg string) {
	switch msg {
	case "start":
		start()
	case "stop":
		stop()
	default:
		panic("Message not understood.")
	}
}

func start() {}

func stop() {}
