package eduoauth

type Logger interface {
    Log(args ...interface{})
    Logf(msg string, args ...interface{})
}

type nullLogger struct {}
func (l nullLogger) Log(args ...interface{}) {}
func (l nullLogger) Logf(msg string, args ...interface{}) {}

var log Logger = nullLogger{}

func UpdateLogger(l Logger) {
	log = l
}
