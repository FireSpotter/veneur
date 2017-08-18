package veneur

import (
	"fmt"
	"time"

	"github.com/DataDog/datadog-go/statsd"
)

type Recorder struct {
	statsd statsd.Client
}

func NewRecorder(conf Config) (*Recorder, error) {
	statsd, err = statsd.NewBuffered(conf.StatsAddress, 1024)
	if err != nil {
		return
	}
	statsd.Namespace = "veneur."
	statsd.Tags = append(conf.Tags, "veneurlocalonly")

	return &Recorder{
		statsd: statsd,
	}
}

func (r *Recorder) PluginFlushDuration(plugin string, start time.Time) {
	r.statsd.TimeInMilliseconds(fmt.Sprintf("flush.plugins.%s.total_duration_ns", service), time.Since(duration).Nanoseconds(), nil, 1.0)
}

func (r *Recorder) PluginFlushErrors(plugin string) {
}

func (r *Recorder) SentryError() {
	r.statsd.Count("sentry.errors_total", 1, nil, 1.0)
}
