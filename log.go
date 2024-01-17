package eduoauth

type Logger interface {
	Log(_ string)
	Logf(_ string, _ ...interface{})
}

type nullLogger struct{}

func (l nullLogger) Log(_ string)            {}
func (l nullLogger) Logf(_ string, _ ...interface{}) {}

var log Logger = nullLogger{}

func UpdateLogger(l Logger) {
	log = l
}
