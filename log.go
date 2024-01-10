package eduoauth

type Logger interface {
	Log(_ ...interface{})
	Logf(_ string, _ ...interface{})
}

type nullLogger struct{}

func (l nullLogger) Log(_ ...interface{})            {}
func (l nullLogger) Logf(_ string, _ ...interface{}) {}

var log Logger = nullLogger{}

func UpdateLogger(l Logger) {
	log = l
}
