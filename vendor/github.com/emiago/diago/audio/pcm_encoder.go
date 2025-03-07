// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: Copyright (c) 2024, Emir Aganovic

package audio

import (
	"encoding/binary"
	"fmt"
	"io"
	"sync"

	"github.com/emiago/diago/media"
	"github.com/rs/zerolog/log"
	"github.com/zaf/g711"
)

/*
	This is PCM Decoder and Encoder (translators from VOIP codecs)
	They are io.Reader io.Writter which should pipeline RTP Reader Writter and pass to upper PCM player
	PCM allows translation to any codec or creating wav files
*/

const (
	// ITU-T G.711.0 codec supports frame lengths of 40, 80, 160, 240 and 320 samples per frame.
	FrameSize  = 3200
	ReadBuffer = 160

	// TODO: this type should defined once. For now we have this on sdp package as well
	FORMAT_TYPE_ULAW = 0
	FORMAT_TYPE_ALAW = 8
	FORMAT_TYPE_OPUS = 96
)

var (
	decoderBufPool = sync.Pool{
		New: func() any {
			return make([]byte, 160)
		},
	}
)

type PCMDecoder struct {
	codec       uint8
	samplesSize int

	// DecoderTo Must know size in advance!
	DecoderTo func(lpcm []byte, encoded []byte) (int, error)
}

// PCM decoder is streamer implementing io.Reader. It reads from underhood reader and returns decoded codec data
// This constructor uses default codec supported by media package.
func NewPCMDecoder(codec uint8) (*PCMDecoder, error) {
	cod, err := media.CodecAudioFromPayloadType(codec)
	if err != nil {
		return nil, err
	}
	dec := &PCMDecoder{}
	return dec, dec.Init(cod)
}

// Init should be called only once after creating PCMDecode
func (dec *PCMDecoder) Init(codec media.Codec) error {
	dec.codec = codec.PayloadType
	dec.samplesSize = codec.SamplesPCM(16) // for now we only support 16 bit

	switch codec.PayloadType {
	case FORMAT_TYPE_ULAW:
		dec.DecoderTo = DecodeUlawTo
	case FORMAT_TYPE_ALAW:
		dec.DecoderTo = DecodeAlawTo
	case FORMAT_TYPE_OPUS:
		opusDec := OpusDecoder{}
		if err := opusDec.Init(int(codec.SampleRate), codec.NumChannels, codec.Samples16()); err != nil {
			return fmt.Errorf("failed to create opus decoder: %w", err)
		}
		dec.DecoderTo = opusDec.DecodeTo
	default:
		return fmt.Errorf("not supported codec %d", codec)
	}
	return nil
}

type PCMDecoderReader struct {
	PCMDecoder
	Source io.Reader
	buf    []byte
}

func NewPCMDecoderReader(codec uint8, reader io.Reader) (*PCMDecoderReader, error) {
	d, err := NewPCMDecoder(codec)
	if err != nil {
		return nil, err
	}

	return &PCMDecoderReader{
		PCMDecoder: *d,
		Source:     reader,
	}, nil
}

// Read decodes and return PCM
// NOTE: It is expected that buffer matches codec samples size.
func (d *PCMDecoderReader) Read(b []byte) (n int, err error) {
	if d.buf == nil {
		d.buf = make([]byte, media.RTPBufSize)
	}

	n, err = d.Source.Read(d.buf)
	if err != nil {
		return n, err
	}

	encoded := d.buf[:n]
	n, err = d.DecoderTo(b, encoded)
	if err != nil {
		return 0, err
	}

	return n, nil
}

type PCMDecoderWriter struct {
	PCMDecoder
	Writer io.Writer
	// DecodeBuf should be increased if you are writing bigger chunk of samples
	DecodeBuf int
	buf       []byte
}

func NewPCMDecoderWriter(codec uint8, writer io.Writer) (*PCMDecoderWriter, error) {
	cod, err := media.CodecAudioFromPayloadType(codec)
	if err != nil {
		return nil, err
	}
	// d, err := NewPCMDecoder(codec)
	// if err != nil {
	// 	return nil, err
	// }
	// return &PCMDecoderWriter{
	// 	PCMDecoder: *d,
	// 	Writer:     writer,
	// }, nil

	dec := &PCMDecoderWriter{}
	return dec, dec.Init(cod, writer)
}

func (d *PCMDecoderWriter) Init(codec media.Codec, writer io.Writer) error {
	d.Writer = writer
	if d.DecodeBuf == 0 {
		d.DecodeBuf = media.RTPBufSize
	}
	return d.PCMDecoder.Init(codec)
}

func (d *PCMDecoderWriter) Write(b []byte) (n int, err error) {
	if d.buf == nil {
		d.buf = make([]byte, d.DecodeBuf)
	}

	// Note size of samples will be decoded
	n, err = d.DecoderTo(d.buf, b)
	if err != nil {
		return 0, err
	}
	lpcm := d.buf[:n]

	nn := 0
	for nn < len(lpcm) {
		n, err = d.Writer.Write(lpcm)
		if err != nil {
			return 0, err
		}
		nn += n
	}

	return len(b), nil
}

type PCMEncoder struct {
	Encoder   func(lpcm []byte) (encoded []byte)
	EncoderTo func(encoded []byte, lpcm []byte) (int, error)

	samplesSize int
}

// PCMEncoder encodes data from pcm to codec and passes to writer
func NewPCMEncoder(payloadType uint8) (*PCMEncoder, error) {
	enc := &PCMEncoder{}
	codec, err := media.CodecAudioFromPayloadType(payloadType)
	if err != nil {
		return nil, err
	}

	return enc, enc.Init(codec)
}

func (enc *PCMEncoder) Init(codec media.Codec) error {
	enc.samplesSize = codec.SamplesPCM(16) // For now we only support 16 bit
	switch codec.PayloadType {
	case FORMAT_TYPE_ULAW:
		enc.Encoder = g711.EncodeUlaw
		enc.EncoderTo = EncodeUlawTo
	case FORMAT_TYPE_ALAW:
		enc.Encoder = g711.EncodeAlaw
		enc.EncoderTo = EncodeAlawTo

	case FORMAT_TYPE_OPUS:
		// TODO handle mono
		opusEnc := OpusEncoder{}
		if err := opusEnc.Init(int(codec.SampleRate), codec.NumChannels, codec.Samples16()); err != nil {
			return fmt.Errorf("failed to create opus decoder: %w", err)
		}
		enc.EncoderTo = opusEnc.EncodeTo

	default:
		return fmt.Errorf("not supported codec %d", codec)
	}
	return nil
}

type PCMEncoderWriter struct {
	PCMEncoder
	Destination io.Writer
	buf         []byte
}

func NewPCMEncoderWriter(codec uint8, writer io.Writer) (*PCMEncoderWriter, error) {
	d, err := NewPCMEncoder(codec)
	if err != nil {
		return nil, err
	}
	return &PCMEncoderWriter{
		PCMEncoder:  *d,
		Destination: writer,
	}, nil
}

func (d *PCMEncoderWriter) Write(lpcm []byte) (int, error) {
	if d.buf == nil {
		// We expect constant rate
		// d.buf = make([]byte, len(lpcm)/2)
		d.buf = make([]byte, media.RTPBufSize)
	}

	// We need to have fixed frame sizes due to encoders

	sampleSize := d.samplesSize
	if len(lpcm) > sampleSize {
		log.Warn().Int("pcm", len(lpcm)).Int("expected", sampleSize).Msg("Size of pcm samples does not match our frame")
	}

	// for i := 0; ; i = i + d.samplesSize {
	// 	lpcmFrame := lpcm[i:]
	// }

	// If encoder can not fit our network buffer it will error
	// TODO we may want this to be configurable for some other applications
	n, err := d.EncoderTo(d.buf, lpcm)
	if err != nil {
		return n, err
	}
	encoded := d.buf[:n]
	// fmt.Println("Writing lpcm, encoded", len(lpcm), len(encoded))

	nn, err := d.Destination.Write(encoded)
	if err != nil {
		return nn, err
	}
	if nn != len(encoded) {
		return 0, io.ErrShortWrite
	}

	return len(lpcm), nil

	// ind := 0
	// nn := 0
	// double := len(d.buf) * 2
	// for nn < len(lpcm) {
	// 	max := min(double, len(lpcm[ind:]))
	// 	// EncoderTo avoids allocation
	// 	n, err := d.EncoderTo(d.buf, lpcm[ind:ind+max])
	// 	if err != nil {
	// 		return 0, err
	// 	}
	// 	ind = max

	// 	encoded := d.buf[:n]
	// 	n, err = d.Destination.Write(encoded)
	// 	if err != nil {
	// 		return nn, err
	// 	}
	// 	if n < len(encoded) {
	// 		return nn, io.ErrShortWrite
	// 	}

	// 	nn += max
	// }
	// return nn, nil
}

func samplesByteToInt16(input []byte, output []int16) (int, error) {
	if len(output) < len(input)/2 {
		return 0, fmt.Errorf("samplesByteToInt16: output is too small buffer. expected=%d, received=%d: %w", len(input)/2, len(output), io.ErrShortBuffer)
	}

	j := 0
	for i := 0; i < len(input); i, j = i+2, j+1 {
		output[j] = int16(binary.LittleEndian.Uint16(input[i : i+2]))
	}
	return len(input) / 2, nil
}

func samplesInt16ToBytes(input []int16, output []byte) (int, error) {
	if len(output) < len(input)*2 {
		return 0, fmt.Errorf("samplesInt16ToBytes: output is too small buffer. expected=%d, received=%d: %w", len(input)*2, len(output), io.ErrShortBuffer)
	}

	j := 0
	for _, sample := range input {
		binary.LittleEndian.PutUint16(output[j:j+2], uint16(sample))
		j += 2
	}
	return len(input) * 2, nil
}
