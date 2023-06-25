package metrics

import (
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
)

// all metrics and middlewares for gRPC and REST API
var (
	// to prevent metrics from being initialized multiple times
	isMetricsInitVar uint32 = 0

	// active REST API connections
	activeRESTConnections = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "active_rest_connections",
			Help: "Number of active REST API connections",
		},
	)

	// number of active gRPC API connections
	activeGRPCConnections = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "active_grpc_connections",
			Help: "Number of active gRPC API connections",
		},
	)

	// response times for REST APIs
	responseTimeRESTAPI = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "restapi_response_time_milliseconds",
			Help:    "REST API response time distributions",
			Buckets: []float64{1, 10, 50, 100, 200, 300, 400, 500},
		},
		[]string{"method", "endpoint"},
	)

	// size of the body for REST APIs
	requestSizeRESTAPI = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "restapi_request_size_kilobytes",
			Help:    "REST API response size distributions",
			Buckets: []float64{200, 500, 900, 1500, 2000, 3000, 4000, 5000},
		},
		[]string{"method", "endpoint"},
	)

	responseSizeRESTAPI = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "restapi_response_size_kilobytes",
			Help:    "REST API response size distributions",
			Buckets: []float64{200, 500, 900, 1500, 2000, 3000, 4000, 5000},
		},
		[]string{"method", "endpoint"},
	)

	// Number of requests processed by gRPC API
	GRPCRequestsMetricsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "grpc_requests_processed_total",
		Help: "The total number of processed gRPC requests",
	}, []string{"method", "endpoint"})

	// Number of requests processed by REST API
	RESTRequestMetricsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "rest_requests_processed_total",
		Help: "The total number of processed REST requests",
	}, []string{"method", "endpoint"})

	// Number of handshake requests received and processed
	HandshakeRequestReceivedMetricsCount = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "handshake_requests_received_total",
		Help: "The total number of received Handshake requests",
	})

	// Number o handshake requests sent to another server
	HandshakeRequestSentMetricsCount = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "handshake_requests_sent_total",
		Help: "The total number of processed Handshake requests sent",
	})

	// Number of Mailio messages sent
	MailioMessagesSentMetricsCount = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "mailio_messages_sent_total",
		Help: "The total number of processed Mailio messages sent",
	})

	// Number of Mailio messages received
	MailioMessagesReceivedMetricsCount = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "mailio_messages_received_total",
		Help: "The total number of processed Mailio messages received",
	})

	// Number of SMTP messages sent
	SMTPMessagesSentMetricsCount = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "smtp_messages_sent_total",
		Help: "The total number of processed SMTP messages sent",
	})

	// Number of SMTP messages received
	SMTPMessagesReceivedMetricsCount = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "smtp_messages_received_total",
		Help: "The total number of processed SMTP messages received",
	})

	// Latency of Handshake gRPC requests
	GRPCHandshakeProcessingLatency = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "grpc_handshake_processing_latency_milliseconds",
		Help:    "Latency of Handshake gRPC requests",
		Buckets: prometheus.LinearBuckets(1, 100, 10),
	})

	// Latency of processing Mailio message sending
	MailioMessageSendProcessingLatency = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "mailio_message_processing_latency_milliseconds",
		Help:    "Latency of Mailio message processing",
		Buckets: prometheus.LinearBuckets(1, 100, 10),
	})

	// Latency of processing of received Mailio message
	MailioMessageReceivedProcessingLatency = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "mailio_message_received_processing_latency_milliseconds",
		Help:    "Latency of Mailio message received processing",
		Buckets: prometheus.LinearBuckets(1, 100, 10),
	})
)

func setIsMetricsInit() {
	atomic.StoreUint32(&isMetricsInitVar, 1)
}

func isMetricsInit() bool {
	return atomic.LoadUint32(&isMetricsInitVar) == 1
}

func InitMetrics() {
	if !isMetricsInit() {
		setIsMetricsInit()

		// Metrics have to be registered to be exposed
		prometheus.MustRegister(activeRESTConnections)
		prometheus.MustRegister(activeGRPCConnections)
		prometheus.MustRegister(responseTimeRESTAPI)
		prometheus.MustRegister(GRPCRequestsMetricsTotal)
		prometheus.MustRegister(RESTRequestMetricsTotal)
		prometheus.MustRegister(HandshakeRequestReceivedMetricsCount)
		prometheus.MustRegister(HandshakeRequestSentMetricsCount)
		prometheus.MustRegister(MailioMessagesSentMetricsCount)
		prometheus.MustRegister(MailioMessagesReceivedMetricsCount)
		prometheus.MustRegister(SMTPMessagesSentMetricsCount)
		prometheus.MustRegister(SMTPMessagesReceivedMetricsCount)
		prometheus.MustRegister(GRPCHandshakeProcessingLatency)
		prometheus.MustRegister(MailioMessageSendProcessingLatency)
		prometheus.MustRegister(MailioMessageReceivedProcessingLatency)
		prometheus.MustRegister(requestSizeRESTAPI)
		prometheus.MustRegister(responseSizeRESTAPI)

	}
}

func MetricsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Increment the counter for the given endpoint:
		RESTRequestMetricsTotal.WithLabelValues(c.Request.Method, c.FullPath()).Inc()

		r := c.Request
		w := c.Writer

		// Start timing responseTime histogram
		start := time.Now()

		// Set activeConnections gauge
		activeRESTConnections.Inc()
		defer activeRESTConnections.Dec()

		c.Next()

		// after request

		// observe request size in kilobtyes
		if r.ContentLength > 0 {
			requestSizeRESTAPI.WithLabelValues(c.Request.Method, c.Request.URL.Path).Observe(float64(r.ContentLength) / 1024)
		}

		// set response size
		if w.Size() > 0 {
			responseSizeRESTAPI.WithLabelValues(c.Request.Method, c.Request.URL.Path).Observe(float64(w.Size()) / 1024)
		}

		// Set responseTime histogram
		latency := time.Since(start)
		responseTimeRESTAPI.WithLabelValues(c.Request.Method, c.Request.URL.Path).Observe(float64(latency.Milliseconds()))
	}
}
