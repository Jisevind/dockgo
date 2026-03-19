package stacks

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"sync"
)

type Logger func(string)

func Deploy(ctx context.Context, stack Stack, log Logger) error {
	if log == nil {
		log = func(string) {}
	}

	validation := Validate(ctx, stack)
	if !validation.Valid {
		return fmt.Errorf("stack validation failed: %s", strings.Join(validation.Issues, "; "))
	}

	log(fmt.Sprintf("Validated stack '%s'.", stack.Name))

	runtimeStack := stack
	runtimeStack.WorkingDir = resolvePathForRuntime(stack, stack.WorkingDir)
	runtimeStack.ComposeFiles = make([]string, 0, len(stack.ComposeFiles))
	for _, composeFile := range stack.ComposeFiles {
		runtimeStack.ComposeFiles = append(runtimeStack.ComposeFiles, resolvePathForRuntime(stack, composeFile))
	}
	runtimeStack.EnvFiles = make([]string, 0, len(stack.EnvFiles))
	for _, envFile := range stack.EnvFiles {
		runtimeStack.EnvFiles = append(runtimeStack.EnvFiles, resolvePathForRuntime(stack, envFile))
	}

	if stack.UpdatePolicy.Pull {
		log("Pulling stack images...")
		if err := streamCommand(ctx, runtimeStack.WorkingDir, log, "docker", append(composeBaseArgs(runtimeStack), "pull")...); err != nil {
			return fmt.Errorf("stack pull failed: %w", err)
		}
	}

	if stack.UpdatePolicy.Build {
		log("Building stack services...")
		buildArgs := append(composeBaseArgs(runtimeStack), "build", "--progress", "plain")
		if err := streamCommand(ctx, runtimeStack.WorkingDir, log, "docker", buildArgs...); err != nil {
			return fmt.Errorf("stack build failed: %w", err)
		}
	}

	if stack.UpdatePolicy.DownBeforeUp {
		log("Bringing stack down before deployment...")
		downArgs := append(composeBaseArgs(runtimeStack), "down")
		if err := streamCommand(ctx, runtimeStack.WorkingDir, log, "docker", downArgs...); err != nil {
			return fmt.Errorf("stack down failed: %w", err)
		}
	}

	upArgs := append(composeBaseArgs(runtimeStack), "up", "-d")
	if stack.UpdatePolicy.RemoveOrphans {
		upArgs = append(upArgs, "--remove-orphans")
	}
	if stack.UpdatePolicy.ForceRecreate {
		upArgs = append(upArgs, "--force-recreate")
	}
	if stack.HealthPolicy.UseComposeWait {
		upArgs = append(upArgs, "--wait")
		if stack.HealthPolicy.WaitTimeoutSeconds > 0 {
			upArgs = append(upArgs, "--wait-timeout", strconv.Itoa(stack.HealthPolicy.WaitTimeoutSeconds))
		}
	}

	log("Deploying stack...")
	if err := streamCommand(ctx, runtimeStack.WorkingDir, log, "docker", upArgs...); err != nil {
		return fmt.Errorf("stack deploy failed: %w", err)
	}

	log("Stack deployment completed successfully.")
	return nil
}

func composeBaseArgs(stack Stack) []string {
	args := []string{"compose"}
	if stack.ProjectName != "" {
		args = append(args, "-p", stack.ProjectName)
	}
	for _, composeFile := range stack.ComposeFiles {
		args = append(args, "-f", composeFile)
	}
	for _, envFile := range stack.EnvFiles {
		args = append(args, "--env-file", envFile)
	}
	if len(stack.Profiles) > 0 {
		for _, profile := range stack.Profiles {
			args = append(args, "--profile", profile)
		}
	}
	return args
}

func streamCommand(ctx context.Context, dir string, log Logger, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir

	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()

	if err := cmd.Start(); err != nil {
		return err
	}

	splitFunc := func(data []byte, atEOF bool) (advance int, token []byte, err error) {
		if atEOF && len(data) == 0 {
			return 0, nil, nil
		}
		if i := bytes.IndexAny(data, "\r\n"); i >= 0 {
			return i + 1, data[0:i], nil
		}
		if atEOF {
			return len(data), data, nil
		}
		return 0, nil, nil
	}

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		scanner := bufio.NewScanner(stdout)
		scanner.Split(splitFunc)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" {
				log(line)
			}
		}
	}()

	go func() {
		defer wg.Done()
		scanner := bufio.NewScanner(stderr)
		scanner.Split(splitFunc)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" {
				log(line)
			}
		}
	}()

	wg.Wait()
	return cmd.Wait()
}
