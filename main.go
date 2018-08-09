// Copyright 2017 John Scherff
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	`bufio`
	`flag`
	`fmt`
	`io`
	`log`
	`os`
	`runtime`
	`sync`
	`time`
	`golang.org/x/crypto/bcrypt`
)

// The wait groups are used by the goroutines to notify the calling
// routine when they are finished.
var (
	wgRead, wgHash, wgWrite sync.WaitGroup
	count int
)

// init parses the command line flags and performs sanity checks.
func init() {

	flag.Parse()

	if *fLogfile != `` {
		if fh, err := os.Create(*fLogfile); err != nil {
			log.Fatal(err)
		} else {
			log.SetOutput(fh)
		}
	}

	if *fCost < bcrypt.MinCost {
		log.Fatalf(`Cost cannot be less than %s`, bcrypt.MinCost)
	}

	if *fCost > bcrypt.MaxCost {
		log.Fatalf(`Cost cannot be more than %s`, bcrypt.MaxCost)
	}

	log.Printf(`Generating hashes with key expansion cost of %d.`, *fCost)

	if *fWorkers <= 0 {
		log.Fatal(`Number of workers must be a positive integer.`)
	}

	log.Printf(`Using %d worker routines to generate hashes.`, *fWorkers)

	if *fQueue <= 0 {
		log.Fatal(`Input queue size must be a positive integer.`)
	}

	log.Printf(`Using a queue size of %d for worker input.`, *fQueue)
}

// readWords takes an io.Reader input and a []byte channel for output.
// It wraps the reader with a line scanner, parses lines from the input
// stream, and queues them on the output channel. It exits when it
// encounters the end of the input stream.
func readWords(reader io.Reader, words chan<- []byte) {

	defer wgRead.Done()

	scanner := bufio.NewScanner(reader)

	for scanner.Scan() {
		words<- []byte(scanner.Text())
		count++
	}

	if err := scanner.Err(); err != nil {
		log.Print(err)
	}
}

// createHash takes a bcrypt cost factor (the two's exponent that 
// defines the number of key expansion rounds) a []byte channel for
// input and a []byte channel for output. It reads lines from the
// input channel, generates a bcrypt hash on the line, and queues
// the result on the output channel. It exits when it encounters
// the end of the input channel.
func createHash(cost int, words <-chan []byte, results chan<- []byte) {

	defer wgHash.Done()

	for {
		word, ok := <-words
		if !ok { break }

		hash, err := bcrypt.GenerateFromPassword(word, cost)

		if err != nil {
			log.Print(err)
		} else {
			results<- []byte(fmt.Sprintf("%s:%s\n", word, hash))
		}
	}
}

// writeReport takes a []byte channel for input and an io.Writer
// for output. It reads hash results from the input channel and
// writes those results to the writer. It exits when it encounters
// the end of the input channel.
func writeReport(writer io.Writer, results <-chan []byte) {

	defer wgWrite.Done()

	for {
		result, ok := <-results
		if !ok { break }

		writer.Write(result)
	}
}

// The main routine sets up the input and output streams and spawns
// the go routines that read the input, generate the hashes, and
// write the output.
func main() {

	var (
		reader io.ReadCloser
		writer io.WriteCloser
		err error
	)

	// Open input file or stdin for reading cleartext data.

	if *fReader == `` {
		reader = os.Stdin
		log.Print(`Using stdin for input.`)
	} else if reader, err = os.Open(*fReader); err != nil {
		log.Fatal(err)
	} else {
		defer reader.Close()
		log.Printf(`Using file '%s' for input.`, *fReader)
	}

	// Open output file or stdout for writing results and 
	// wrap it with a buffered writer.

	if *fWriter == `` {
		writer = os.Stdout
		log.Print(`Using stdout for output.`)
	} else if writer, err = os.Create(*fWriter); err != nil {
		log.Fatal(err)
	} else {
		defer writer.Close()
		log.Printf(`Using file '%s' for output.`, *fWriter)
	}

	bufwriter := bufio.NewWriter(writer)

	// Create buffered channels for input lines and hash results.

	words := make(chan []byte, *fQueue)
	results := make(chan []byte, *fQueue)

	// Start a timer and log processing time.

	start := time.Now()
	defer func() {
		elapsed := time.Since(start)
		log.Printf(`Processed %d records in %s`, count, elapsed)
	}()

	// Spawn the input goroutine.

	wgRead.Add(1)
	go readWords(reader, words)

	// Spawn the hashing goroutines.

	wgHash.Add(*fWorkers)
	for i := 1; i <= *fWorkers; i++ {
		go createHash(*fCost, words, results)
	}

	log.Printf(`Total active goroutines: %d.`, runtime.NumGoroutine())

	// Spawn the output goroutine.
	wgWrite.Add(1)
	go writeReport(bufwriter, results)

	// wait for the reader and hashing goroutines to finish, then
	// close their associated output channels.

	wgRead.Wait()
	close(words)

	wgHash.Wait()
	close(results)

	// Wait for the writer goroutine to finish, then flush the
	// buffered writer and exit.

	wgWrite.Wait()
	bufwriter.Flush()
}
