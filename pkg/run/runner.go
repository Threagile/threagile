// TODO: consider moving to internal
package run

import (
	"encoding/json"
	"fmt"
	"io"
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

	stdout, stdoutError := plugin.StdoutPipe()
	if stdoutError != nil {
		return stdoutError
	}
	defer func() { _ = stdout.Close() }()

	stderr, stderrError := plugin.StderrPipe()
	if stderrError != nil {
		return stderrError
	}
	defer func() { _ = stderr.Close() }()

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

	errData, errError := io.ReadAll(stderr)
	if errError != nil {
		return errError
	}
	p.ErrorOutput = string(errData)

	outData, outError := io.ReadAll(stdout)
	if outError != nil {
		return outError
	}

	waitError := plugin.Wait()
	if waitError != nil {
		return fmt.Errorf("%v: %v", waitError, p.ErrorOutput)
	}

	unmarshalError := json.Unmarshal(outData, &p.Out)
	if unmarshalError != nil {
		return unmarshalError
	}

	return nil
}
