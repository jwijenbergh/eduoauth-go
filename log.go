package eduoauth

// Logger defines the interface for logging
// You can set your own Logger with `UpdateLogger`
type Logger interface {
	Log(_ string)
	Logf(_ string, _ ...interface{})
}

type nullLogger struct{}

func (l nullLogger) Log(_ string)                    {}
func (l nullLogger) Logf(_ string, _ ...interface{}) {}

var log Logger = nullLogger{}

// UpdateLogger updates the internal logger used with `l`
func UpdateLogger(l Logger) {
	log = l
}
