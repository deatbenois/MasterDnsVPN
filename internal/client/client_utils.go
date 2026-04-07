// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================
// Package client provides the core logic for the MasterDnsVPN client.
// This file (client_utils.go) handles common client utility functions.
// ==============================================================================
package client

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"masterdnsvpn-go/internal/arq"
	Enums "masterdnsvpn-go/internal/enums"
	"masterdnsvpn-go/internal/logger"
	"masterdnsvpn-go/internal/version"
	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

// randomBytes generates random bytes using a cryptographically secure PRNG.
// This is used for generating sensitive identifiers like session codes and verify tokens.
func randomBytes(length int) ([]byte, error) {
	if length <= 0 {
		return []byte{}, nil
	}
	buf := make([]byte, length)
	if _, err := rand.Read(buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// fragmentPayload splits a payload into chunks of max mtu size.
func fragmentPayload(payload []byte, mtu int) [][]byte {
	if len(payload) <= mtu {
		return [][]byte{payload}
	}
	var fragments [][]byte
	for i := 0; i < len(payload); i += mtu {
		end := i + mtu
		if end > len(payload) {
			end = len(payload)
		}
		fragments = append(fragments, payload[i:end])
	}
	return fragments
}

func formatResolverEndpoint(resolver string, port int) string {
	if strings.IndexByte(resolver, ':') >= 0 && !strings.HasPrefix(resolver, "[") {
		return fmt.Sprintf("[%s]:%d", resolver, port)
	}
	return fmt.Sprintf("%s:%d", resolver, port)
}

func makeConnectionKey(resolver string, port int, domain string) string {
	return resolver + "|" + strconv.Itoa(port) + "|" + domain
}

func isHotPacketLogType(packetType uint8) bool {
	switch packetType {
	case Enums.PACKET_STREAM_DATA,
		Enums.PACKET_STREAM_DATA_ACK,
		Enums.PACKET_STREAM_DATA_NACK,
		Enums.PACKET_STREAM_RESEND,
		Enums.PACKET_PACKED_CONTROL_BLOCKS,
		Enums.PACKET_PING,
		Enums.PACKET_PONG:
		return true
	default:
		return false
	}
}

func (c *Client) logInboundPacket(packetType uint8, sessionID uint8, payloadLen int, streamID uint16, sequenceNum uint16, fragmentID uint8, totalFragments uint8, packedSummary string) {
	if c == nil || c.log == nil || packetType == Enums.PACKET_PONG {
		return
	}
	format := "<green>Receiving Packet, Packet: %s | Session %d | Payload Len(%d) | Stream: %d | Seq: %d | Fg: %d | TF: %d%s</green>"
	if isHotPacketLogType(packetType) {
		if c.log.Enabled(logger.LevelDebug) {
			c.log.Debugf(format, Enums.PacketTypeName(packetType), sessionID, payloadLen, streamID, sequenceNum, fragmentID, totalFragments, packedSummary)
		}
		return
	}
	c.log.Debugf(format, Enums.PacketTypeName(packetType), sessionID, payloadLen, streamID, sequenceNum, fragmentID, totalFragments, packedSummary)
}

func (c *Client) logOutboundPacket(packetType uint8, sessionID uint8, payloadLen int, streamID uint16, sequenceNum uint16, fragmentID uint8, totalFragments uint8, packedSummary string) {
	if c == nil || c.log == nil || packetType == Enums.PACKET_PING {
		return
	}
	format := "<cyan>Sending Packet, Packet: Packet: %s | Session %d | Payload Len(%d) | Stream: %d | Seq: %d | Fg: %d | TF: %d%s</cyan>"
	if isHotPacketLogType(packetType) {
		if c.log.Enabled(logger.LevelDebug) {
			c.log.Debugf(format, Enums.PacketTypeName(packetType), sessionID, payloadLen, streamID, sequenceNum, fragmentID, totalFragments, packedSummary)
		}
		return
	}
	c.log.Debugf(format, Enums.PacketTypeName(packetType), sessionID, payloadLen, streamID, sequenceNum, fragmentID, totalFragments, packedSummary)
}

func (c *Client) getResolverUDPAddr(conn Connection) (*net.UDPAddr, error) {
	if c == nil {
		return nil, ErrNoValidConnections
	}

	label := conn.ResolverLabel
	if label == "" {
		label = formatResolverEndpoint(conn.Resolver, conn.ResolverPort)
	}

	c.resolverAddrMu.RLock()
	if addr, ok := c.resolverAddrCache[label]; ok && addr != nil {
		c.resolverAddrMu.RUnlock()
		return addr, nil
	}
	c.resolverAddrMu.RUnlock()

	var addr *net.UDPAddr
	if ip := net.ParseIP(conn.Resolver); ip != nil {
		addr = &net.UDPAddr{IP: ip, Port: conn.ResolverPort}
	} else {
		resolved, err := net.ResolveUDPAddr("udp", label)
		if err != nil {
			return nil, err
		}
		addr = resolved
	}

	c.resolverAddrMu.Lock()
	if existing, ok := c.resolverAddrCache[label]; ok && existing != nil {
		c.resolverAddrMu.Unlock()
		return existing, nil
	}
	c.resolverAddrCache[label] = addr
	c.resolverAddrMu.Unlock()
	return addr, nil
}

// now returns the current time.
func (c *Client) now() time.Time {
	if c != nil && c.nowFn != nil {
		return c.nowFn()
	}
	return time.Now()
}

func (c *Client) bumpStreamSetVersion() {
	if c == nil {
		return
	}
	c.streamSetVersion.Add(1)
}

func (c *Client) SessionReady() bool {
	if c == nil {
		return false
	}
	return c.sessionReady
}

func (c *Client) SessionID() uint8 {
	return c.sessionID
}

func (c *Client) IsSessionReady() bool {
	return c.SessionReady()
}

func (c *Client) ResponseMode() uint8 {
	return c.responseMode
}

func (c *Client) NotifyPacket(packetType uint8, isInbound bool) {
	if c.pingManager != nil {
		c.pingManager.NotifyPacket(packetType, isInbound)
	}
}

func (c *Client) Log() *logger.Logger {
	return c.log
}

// connectionPtrByKey remains as a bridge, now fetching from Balancer.
func (c *Client) connectionPtrByKey(key string) *Connection {
	if c.balancer == nil {
		return nil
	}
	conn, ok := c.balancer.GetConnectionByKey(key)
	if !ok {
		return nil
	}
	return &conn
}

func (c *Client) GetConnectionByKey(key string) (Connection, bool) {
	if c == nil || c.balancer == nil || key == "" {
		return Connection{}, false
	}
	return c.balancer.GetConnectionByKey(key)
}

func orphanResetKey(packetType uint8, streamID uint16) uint64 {
	return Enums.PacketTypeStreamKey(streamID, packetType)
}

func (c *Client) enqueueOrphanReset(packetType uint8, streamID uint16, sequenceNum uint16) {
	if c == nil || c.orphanQueue == nil || streamID == 0 {
		return
	}

	packet := VpnProto.Packet{
		PacketType:     packetType,
		StreamID:       streamID,
		HasStreamID:    true,
		SequenceNum:    sequenceNum,
		HasSequenceNum: sequenceNum != 0,
	}

	key := orphanResetKey(packetType, streamID)
	// Orphans usually have high priority. We'll use priority 0.
	c.orphanQueue.Push(0, key, packet)

	select {
	case c.dispatchSignal <- struct{}{}:
	default:
	}
}

func (c *Client) clearOrphanResets() {
	if c == nil || c.orphanQueue == nil {
		return
	}
	c.orphanQueue.Clear(nil)
}

func (c *Client) queueImmediateControlAck(stream *Stream_client, packet VpnProto.Packet) bool {
	if c == nil {
		return false
	}

	ackType, ok := Enums.ControlAckFor(packet.PacketType)
	if !ok {
		return false
	}

	if stream == nil || stream.txQueue == nil {
		return false
	}

	ok = stream.PushTXPacket(
		Enums.DefaultPacketPriority(ackType),
		ackType,
		packet.SequenceNum,
		packet.FragmentID,
		packet.TotalFragments,
		0,
		0,
		nil,
	)

	return ok
}

func (c *Client) consumeInboundStreamAck(packetType uint8, packet VpnProto.Packet, s *Stream_client) bool {
	if c == nil || s == nil {
		return false
	}

	_, ack_required := Enums.ReverseControlAckFor(packetType)
	if packetType != Enums.PACKET_STREAM_DATA_ACK && !ack_required {
		return false
	}

	if packetType == Enums.PACKET_STREAM_RST_ACK {
		c.rememberClosedStream(packet.StreamID, "ACK acknowledged", time.Now())
	}

	arqObj, ok := s.Stream.(*arq.ARQ)
	if !ok {
		return false
	}

	handledAck := arqObj.HandleAckPacket(packet.PacketType, packet.SequenceNum, packet.FragmentID)
	if handledAck {
		c.balancer.NoteStreamProgress(packet.StreamID)
	}

	if _, ok := Enums.GetPacketCloseStream(packet.PacketType); handledAck && ok {
		if s.StatusValue() == streamStatusCancelled || arqObj.IsClosed() {
			s.MarkTerminal(time.Now())
			if s.StatusValue() != streamStatusCancelled {
				s.SetStatus(streamStatusTimeWait)
			}
		}
	}

	if handledAck {
		return true
	}

	return false
}

func (c *Client) getStream(streamID uint16) (*Stream_client, bool) {
	c.streamsMu.RLock()
	s, ok := c.active_streams[streamID]
	c.streamsMu.RUnlock()
	return s, ok
}

func (c *Client) shouldRememberClosedStream(reason string) bool {
	if c == nil {
		return false
	}

	reason = strings.TrimSpace(reason)
	if reason == "" {
		return false
	}

	if reason == "close handshake completed" || reason == "client local disconnect completed" {
		return true
	}

	return strings.HasSuffix(reason, "acknowledged")
}

func (c *Client) rememberClosedStream(streamID uint16, reason string, now time.Time) {
	if c == nil || streamID == 0 || !c.shouldRememberClosedStream(reason) {
		return
	}

	retention := c.cfg.ClientTerminalStreamRetention()
	if retention <= 0 {
		retention = 15 * time.Second
	}

	c.recentlyClosedMu.Lock()
	// Cap the map to prevent unbounded growth during long sessions.
	// If at limit, evict the oldest entry before adding.
	const maxRecentlyClosed = 2000
	if len(c.recentlyClosedStreams) >= maxRecentlyClosed {
		var oldestID uint16
		var oldestTime time.Time
		for id, t := range c.recentlyClosedStreams {
			if oldestTime.IsZero() || t.Before(oldestTime) {
				oldestID = id
				oldestTime = t
			}
		}
		delete(c.recentlyClosedStreams, oldestID)
	}
	c.recentlyClosedStreams[streamID] = now.Add(retention)
	c.recentlyClosedMu.Unlock()
}

func (c *Client) isRecentlyClosedStream(streamID uint16, now time.Time) bool {
	if c == nil || streamID == 0 {
		return false
	}

	c.recentlyClosedMu.Lock()
	defer c.recentlyClosedMu.Unlock()

	expiresAt, ok := c.recentlyClosedStreams[streamID]
	if !ok {
		return false
	}
	if now.Before(expiresAt) {
		return true
	}

	delete(c.recentlyClosedStreams, streamID)
	return false
}

func (c *Client) cleanupRecentlyClosedStreams(now time.Time) {
	if c == nil {
		return
	}

	c.recentlyClosedMu.Lock()
	for streamID, expiresAt := range c.recentlyClosedStreams {
		if !now.Before(expiresAt) {
			delete(c.recentlyClosedStreams, streamID)
		}
	}
	c.recentlyClosedMu.Unlock()
}

func (c *Client) clearRecentlyClosedStreams() {
	if c == nil {
		return
	}

	c.recentlyClosedMu.Lock()
	clear(c.recentlyClosedStreams)
	c.recentlyClosedMu.Unlock()
}

func (c *Client) handleMissingStreamPacket(packet VpnProto.Packet) bool {
	if c == nil {
		return false
	}

	if packet.PacketType == Enums.PACKET_PACKED_CONTROL_BLOCKS ||
		packet.PacketType == Enums.PACKET_PONG ||
		packet.PacketType == Enums.PACKET_DNS_QUERY_RES {
		return false
	}

	// No need to send Response for ACK packets
	if packet.PacketType == Enums.PACKET_STREAM_DATA_ACK || packet.PacketType == Enums.PACKET_STREAM_DATA_NACK {
		return true
	}

	if packet.PacketType == Enums.PACKET_STREAM_RST_ACK {
		c.rememberClosedStream(packet.StreamID, "ACK acknowledged", time.Now())
	}

	if _, ok := Enums.ReverseControlAckFor(packet.PacketType); ok {
		return true
	}

	if packet.PacketType == Enums.PACKET_STREAM_RST {
		c.enqueueOrphanReset(Enums.PACKET_STREAM_RST_ACK, packet.StreamID, packet.SequenceNum)
		return true
	}

	// GetPacketCloseStream
	ack_answer, ok := Enums.GetPacketCloseStream(packet.PacketType)
	if ok {
		c.enqueueOrphanReset(ack_answer, packet.StreamID, 0)
	} else {
		c.enqueueOrphanReset(Enums.PACKET_STREAM_RST, packet.StreamID, 0)
	}

	return true
}

func (c *Client) ackRecentlyClosedStreamPacket(packet VpnProto.Packet) bool {
	if c == nil || packet.StreamID == 0 {
		return false
	}

	if packet.PacketType == Enums.PACKET_STREAM_DATA_ACK || packet.PacketType == Enums.PACKET_STREAM_DATA_NACK {
		return true
	}

	if _, ok := Enums.ReverseControlAckFor(packet.PacketType); ok {
		return true
	}

	if ackType, ok := Enums.ControlAckFor(packet.PacketType); ok {
		c.enqueueOrphanReset(ackType, packet.StreamID, packet.SequenceNum)
		return true
	}

	return false
}

func (c *Client) preprocessInboundPacket(packet VpnProto.Packet) bool {
	if c == nil {
		return true
	}

	exists_stream, stream_exists := c.getStream(packet.StreamID)
	if packet.StreamID != 0 && (!stream_exists || exists_stream == nil) {
		if c.isRecentlyClosedStream(packet.StreamID, c.now()) {
			if packet.PacketType == Enums.PACKET_STREAM_DATA ||
				packet.PacketType == Enums.PACKET_STREAM_RESEND {
				c.enqueueOrphanReset(Enums.PACKET_STREAM_RST, packet.StreamID, 0)
				return true
			}
			if c.ackRecentlyClosedStreamPacket(packet) {
				return true
			}
			return true
		}

		c.handleMissingStreamPacket(packet)
		return true
	}

	// Add ACK to queue if thats control packet
	_ = c.queueImmediateControlAck(exists_stream, packet)

	// Handle all control packets
	if c.consumeInboundStreamAck(packet.PacketType, packet, exists_stream) {
		return true
	}

	return false
}

func (c *Client) PreprocessInboundPacket(packet VpnProto.Packet) bool {
	return c.preprocessInboundPacket(packet)
}

func (c *Client) getStreamARQ(streamID uint16) (*arq.ARQ, error) {
	c.streamsMu.RLock()
	s, ok := c.active_streams[streamID]
	c.streamsMu.RUnlock()

	if !ok || s == nil {
		return nil, fmt.Errorf("stream not found")
	}

	arqObj, ok := s.Stream.(*arq.ARQ)
	if !ok {
		return nil, fmt.Errorf("stream is not ARQ")
	}
	return arqObj, nil
}

func (c *Client) Balancer() *Balancer {
	return c.balancer
}

func (c *Client) ShortPrintBanner() {
	if c.log == nil {
		return
	}

	c.log.Infof("============================================================")
	c.log.Infof("<cyan>GitHub:</cyan> <yellow>https://github.com/masterking32/MasterDnsVPN</yellow>")
	c.log.Infof("<cyan>Telegram:</cyan> <yellow>@MasterDnsVPN</yellow>")
	c.log.Infof("<cyan>Build Version:</cyan> <yellow>%s</yellow>", version.GetVersion())
	c.log.Infof("============================================================")
}

func (c *Client) PrintBanner() {
	if c.log == nil {
		return
	}

	c.ShortPrintBanner()
	c.log.Infof("🚀 <green>Client Configuration Loaded</green>")

	c.log.Infof("🚀 <cyan>Client Mode, Protocol:</cyan> <yellow>%s</yellow> <cyan>Encryption:</cyan> <yellow>%d</yellow>", c.cfg.ProtocolType, c.cfg.DataEncryptionMethod)

	strategyName := "Round-Robin"
	switch c.cfg.ResolverBalancingStrategy {
	case 0:
		strategyName = "Round-Robin Default"
	case 1:
		strategyName = "Random"
	case 2:
		strategyName = "Round-Robin"
	case 3:
		strategyName = "Least Loss"
	case 4:
		strategyName = "Lowest Latency"
	}
	c.log.Infof("⚖  <cyan>Resolver Balancing, Strategy:</cyan> <yellow>%s (%d)</yellow>", strategyName, c.cfg.ResolverBalancingStrategy)

	domainList := ""
	if len(c.cfg.Domains) > 0 {
		domainList = c.cfg.Domains[0]
	}
	c.log.Infof("🌐 <cyan>Configured Domains:</cyan> <yellow>%d (%s)</yellow>", len(c.cfg.Domains), domainList)
	c.log.Infof("📡 <cyan>Loaded Resolvers:</cyan> <yellow>%d endpoints.</yellow>", len(c.cfg.Resolvers))
}

// BuildConnectionMap iterates through all domains and resolvers in the configuration
// and builds a comprehensive list of unique Connection objects, then entrusts them to the Balancer.
func (c *Client) BuildConnectionMap() error {
	domains := c.cfg.Domains
	resolvers := c.cfg.Resolvers

	total := len(domains) * len(resolvers)
	if total <= 0 {
		return fmt.Errorf("Domains or Resolvers are missing in config.")
	}

	connections := make([]Connection, 0, total)
	indexByKey := make(map[string]int, total)

	for _, domain := range domains {
		for _, resolver := range resolvers {
			label := formatResolverEndpoint(resolver.IP, resolver.Port)
			key := makeConnectionKey(resolver.IP, resolver.Port, domain)
			if _, exists := indexByKey[key]; exists {
				continue
			}

			indexByKey[key] = len(connections)
			connections = append(connections, Connection{
				Domain:        domain,
				Resolver:      resolver.IP,
				ResolverPort:  resolver.Port,
				ResolverLabel: label,
				Key:           key,
				IsValid:       false, // Initially all are inactive until MTU/Health checks pass
			})
			if ip := net.ParseIP(resolver.IP); ip != nil {
				c.resolverAddrMu.Lock()
				c.resolverAddrCache[label] = &net.UDPAddr{IP: ip, Port: resolver.Port}
				c.resolverAddrMu.Unlock()
			}
		}
	}

	pointers := make([]*Connection, len(connections))
	for i := range connections {
		pointers[i] = &connections[i]
	}

	if c.balancer != nil {
		c.balancer.SetConnections(pointers)
	}

	return nil
}

const (
	resolverPendingSoftCap   = 8192
	resolverPendingHardCap   = 12288
	resolverPendingTargetCap = 8192
)

func (c *Client) resolverSampleTTL() time.Duration {
	if c == nil {
		return 15 * time.Second
	}

	ttl := c.tunnelPacketTimeout * 3
	if ttl < 10*time.Second {
		ttl = 10 * time.Second
	}
	if ttl > 45*time.Second {
		ttl = 45 * time.Second
	}
	return ttl
}

func (c *Client) noteResolverSend(serverKey string) {
	if c == nil || c.balancer == nil || serverKey == "" {
		return
	}
	now := c.now()
	window := c.autoDisableTimeoutWindow()
	c.balancer.ReportSend(serverKey)
	c.balancer.ReportSendWindow(serverKey, now, window)
}

func (c *Client) noteResolverSuccess(serverKey string, rtt time.Duration) {
	if c == nil || c.balancer == nil || serverKey == "" {
		return
	}
	c.balancer.ReportSuccessWindow(serverKey, c.now(), c.autoDisableTimeoutWindow(), rtt)
}

func (c *Client) noteResolverTimeout(serverKey string, at time.Time) {
	if c == nil || c.balancer == nil || serverKey == "" {
		return
	}
	if at.IsZero() {
		at = c.now()
	}
	if !c.cfg.AutoDisableTimeoutServers {
		return
	}
	c.balancer.ReportTimeoutWindow(
		serverKey,
		at,
		c.autoDisableTimeoutWindow(),
		c.autoDisableMinObservations(),
		1,
	)
}

func (c *Client) noteResolverFailure(serverKey string, at time.Time) {
	if c == nil || c.balancer == nil || serverKey == "" {
		return
	}
	if at.IsZero() {
		at = c.now()
	}
	if !c.cfg.AutoDisableTimeoutServers {
		return
	}
	c.balancer.ReportTimeoutWindow(
		serverKey,
		at,
		c.autoDisableTimeoutWindow(),
		c.autoDisableMinObservations(),
		1,
	)
}

func (c *Client) retractResolverTimeoutEvent(serverKey string, timedOutAt time.Time, now time.Time) {
	if c == nil || c.balancer == nil || serverKey == "" || timedOutAt.IsZero() {
		return
	}
	c.balancer.RetractTimeoutWindow(serverKey, now, c.autoDisableTimeoutWindow())
}

func (c *Client) trackResolverSend(packet []byte, resolverAddr string, localAddr string, serverKey string, sentAt time.Time) {
	if c == nil || len(packet) < 2 || resolverAddr == "" || serverKey == "" {
		return
	}

	key := resolverSampleKey{
		resolverAddr: resolverAddr,
		localAddr:    localAddr,
		dnsID:        binary.BigEndian.Uint16(packet[:2]),
	}

	var timeoutObservations []resolverTimeoutObservation
	c.resolverStatsMu.Lock()
	if len(c.resolverPending) >= resolverPendingSoftCap {
		timeoutObservations = c.pruneResolverSamplesLocked(sentAt)
		if overflow := len(c.resolverPending) - resolverPendingHardCap; overflow >= 0 {
			c.evictResolverPendingLocked(overflow + 1)
		}
	}
	c.resolverPending[key] = resolverSample{
		serverKey: serverKey,
		sentAt:    sentAt,
	}
	c.resolverStatsMu.Unlock()

	for _, observation := range timeoutObservations {
		c.noteResolverTimeout(observation.serverKey, observation.at)
	}
	c.noteResolverSend(serverKey)
}

func (c *Client) trackResolverSuccess(packet []byte, addr *net.UDPAddr, localAddr string, receivedAt time.Time) {
	if c == nil || len(packet) < 2 || addr == nil {
		return
	}

	key := resolverSampleKey{
		resolverAddr: addr.String(),
		localAddr:    localAddr,
		dnsID:        binary.BigEndian.Uint16(packet[:2]),
	}

	c.resolverStatsMu.Lock()
	sample, ok := c.resolverPending[key]
	if ok {
		delete(c.resolverPending, key)
	}
	c.resolverStatsMu.Unlock()

	if !ok || sample.serverKey == "" {
		return
	}

	if sample.timedOut && !sample.timedOutAt.IsZero() {
		c.retractResolverTimeoutEvent(sample.serverKey, sample.timedOutAt, receivedAt)
	}

	c.noteResolverSuccess(sample.serverKey, receivedAt.Sub(sample.sentAt))
}

func (c *Client) trackResolverFailure(packet []byte, addr *net.UDPAddr, localAddr string, failedAt time.Time) {
	if c == nil || len(packet) < 2 || addr == nil {
		return
	}

	key := resolverSampleKey{
		resolverAddr: addr.String(),
		localAddr:    localAddr,
		dnsID:        binary.BigEndian.Uint16(packet[:2]),
	}

	c.resolverStatsMu.Lock()
	sample, ok := c.resolverPending[key]
	if ok {
		delete(c.resolverPending, key)
	}
	c.resolverStatsMu.Unlock()

	if !ok || sample.serverKey == "" || sample.timedOut {
		return
	}

	c.noteResolverFailure(sample.serverKey, failedAt)
}

func (c *Client) collectExpiredResolverTimeouts(now time.Time) {
	if c == nil {
		return
	}
	c.resolverStatsMu.Lock()
	timeoutObservations := c.pruneResolverSamplesLocked(now)
	c.resolverStatsMu.Unlock()
	for _, observation := range timeoutObservations {
		c.noteResolverTimeout(observation.serverKey, observation.at)
	}
}

func (c *Client) resolverRequestTimeout() time.Duration {
	if c == nil {
		return 5 * time.Second
	}
	timeout := c.tunnelPacketTimeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	if checkInterval := c.autoDisableCheckInterval(); checkInterval > 0 && checkInterval < timeout {
		timeout = checkInterval
	}
	if window := c.autoDisableTimeoutWindow(); window > 0 && window < timeout {
		timeout = window
	}
	if timeout < 500*time.Millisecond {
		timeout = 500 * time.Millisecond
	}
	return timeout
}

func (c *Client) autoDisableTimeoutWindow() time.Duration {
	if c == nil || !c.cfg.AutoDisableTimeoutServers {
		return 0
	}
	window := time.Duration(c.cfg.AutoDisableTimeoutWindowSeconds * float64(time.Second))
	if window <= 0 {
		return 0
	}
	return window
}

func (c *Client) autoDisableCheckInterval() time.Duration {
	if c == nil || !c.cfg.AutoDisableTimeoutServers {
		return 0
	}
	interval := time.Duration(c.cfg.AutoDisableCheckIntervalSeconds * float64(time.Second))
	if interval <= 0 {
		return 0
	}
	return interval
}

func (c *Client) autoDisableMinObservations() int {
	if c == nil {
		return 1
	}
	if c.cfg.AutoDisableMinObservations < 1 {
		return 1
	}
	return c.cfg.AutoDisableMinObservations
}

func (c *Client) resolverLateResponseGrace(timeout time.Duration) time.Duration {
	if timeout <= 0 {
		timeout = c.resolverRequestTimeout()
	}
	grace := timeout * 3
	if grace < time.Second {
		grace = time.Second
	}
	maxTTL := c.resolverSampleTTL()
	if grace > maxTTL {
		grace = maxTTL
	}
	return grace
}

func (c *Client) pruneResolverSamplesLocked(now time.Time) []resolverTimeoutObservation {
	if c == nil || len(c.resolverPending) == 0 {
		return nil
	}

	timeoutBefore := now.Add(-c.resolverRequestTimeout())
	absoluteCutoff := now.Add(-c.resolverSampleTTL())
	requestTimeout := c.resolverRequestTimeout()
	lateGrace := c.resolverLateResponseGrace(requestTimeout)
	var timeoutObservations []resolverTimeoutObservation
	for key, sample := range c.resolverPending {
		if !sample.timedOut {
			if !sample.sentAt.After(timeoutBefore) {
				sample.timedOut = true
				sample.timedOutAt = sample.sentAt.Add(requestTimeout)
				if sample.timedOutAt.After(now) {
					sample.timedOutAt = now
				}
				sample.evictAfter = sample.timedOutAt.Add(lateGrace)
				c.resolverPending[key] = sample
				if sample.serverKey != "" {
					timeoutObservations = append(timeoutObservations, resolverTimeoutObservation{
						serverKey: sample.serverKey,
						at:        sample.timedOutAt,
					})
				}
			}
			if sample.sentAt.Before(absoluteCutoff) {
				delete(c.resolverPending, key)
			}
			continue
		}

		if !sample.evictAfter.IsZero() && !sample.evictAfter.After(now) {
			delete(c.resolverPending, key)
			continue
		}
		if sample.sentAt.Before(absoluteCutoff) {
			delete(c.resolverPending, key)
		}
	}
	return timeoutObservations
}

func (c *Client) evictResolverPendingLocked(evictCount int) {
	if c == nil || evictCount <= 0 || len(c.resolverPending) == 0 {
		return
	}

	type pendingEntry struct {
		key    resolverSampleKey
		sample resolverSample
	}

	entries := make([]pendingEntry, 0, len(c.resolverPending))
	for key, sample := range c.resolverPending {
		entries = append(entries, pendingEntry{key: key, sample: sample})
	}

	sort.Slice(entries, func(i, j int) bool {
		if entries[i].sample.timedOut != entries[j].sample.timedOut {
			return entries[i].sample.timedOut
		}
		if !entries[i].sample.sentAt.Equal(entries[j].sample.sentAt) {
			return entries[i].sample.sentAt.Before(entries[j].sample.sentAt)
		}
		if entries[i].key.resolverAddr != entries[j].key.resolverAddr {
			return entries[i].key.resolverAddr < entries[j].key.resolverAddr
		}
		return entries[i].key.dnsID < entries[j].key.dnsID
	})

	if evictCount > len(entries) {
		evictCount = len(entries)
	}
	for i := 0; i < evictCount; i++ {
		delete(c.resolverPending, entries[i].key)
	}
}
