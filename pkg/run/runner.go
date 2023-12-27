// TODO: consider moving to internal
package run

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
)

type Runner struct {
	Filename    string
	Parameters  []string
	In          any
	Out         any
	ErrorOutput string
}

func (p *Runner) Load(filename string) (*Runner, error) {
	*p = Runner{
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

func (p *Runner) Run(in any, out any, parameters ...string) error {
	*p = Runner{
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
	if waitError != nil {
		return fmt.Errorf("%v: %v", waitError, p.ErrorOutput)
	}

	p.ErrorOutput = stderrBuf.String()
	stdout := stdoutBuf.Bytes()

	unmarshalError := json.Unmarshal(stdout, &p.Out)
	if unmarshalError != nil {
		return unmarshalError
	}

	return nil
}