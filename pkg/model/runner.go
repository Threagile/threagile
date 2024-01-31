// TODO: consider moving to internal
package model

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
)

type runner struct {
	Filename    string
	Parameters  []string
	In          any
	Out         any
	ErrorOutput string
}

func (p *runner) Load(filename string) (*runner, error) {
	*p = runner{
		Filename: filename,
	}

	fileInfo, statError := os.Stat(filename)
	if statError != nil {
		return p, statError
	}

	if !fileInfo.Mode().IsRegular() {
		return p, fmt.Errorf("run %q is not a regular file", filename)
	}

	return p, nil
}

func (p *runner) Run(in any, out any, parameters ...string) error {
	*p = runner{
		Filename:   p.Filename,
		Parameters: parameters,
		In:         in,
		Out:        out,
	}

	plugin := exec.Command(p.Filename, p.Parameters...)
	stdin, stdinError := plugin.StdinPipe()
	if stdinError != nil {
		return stdinError
	}
	defer func() { _ = stdin.Close() }()

	var stdoutBuf bytes.Buffer
	plugin.Stdout = &stdoutBuf

	var stderrBuf bytes.Buffer
	plugin.Stderr = &stderrBuf

	startError := plugin.Start()
	if startError != nil {
		return startError
	}

	inData, inError := json.MarshalIndent(p.In, "", "  ")
	if inError != nil {
		return inError
	}

	_, writeError := stdin.Write(inData)
	if writeError != nil {
		return writeError
	}

	inCloseError := stdin.Close()
	if inCloseError != nil {
		return inCloseError
	}

	waitError := plugin.Wait()
	p.ErrorOutput = stderrBuf.String()
	if waitError != nil {
		return fmt.Errorf("%v: %v", waitError, p.ErrorOutput)
	}

	stdout := stdoutBuf.Bytes()
	unmarshalError := json.Unmarshal(stdout, &p.Out)
	if unmarshalError != nil {
		return unmarshalError
	}

	return nil
}
