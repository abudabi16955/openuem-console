package models

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/open-uem/ent/agent"
	"github.com/open-uem/ent/enttest"
	"github.com/open-uem/ent/task"
	"github.com/open-uem/ent/taskreport"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type TasksTestSuite struct {
	suite.Suite
	t     enttest.TestingT
	model Model
}

func (suite *TasksTestSuite) SetupTest() {
	client := enttest.Open(suite.t, "sqlite3", "file:ent?mode=memory&_fk=1")
	suite.model = Model{Client: client}
}

func (suite *TasksTestSuite) TestTaskTimeoutAndExecutionReports() {
	ctx := context.Background()

	// 1. Create a profile
	p, err := suite.model.Client.Profile.Create().SetName("Test Profile").Save(ctx)
	assert.NoError(suite.T(), err)

	// 2. Add a task with Timeout
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	cfg := TaskConfig{
		Description: "Install Winget package",
		TaskType:    task.TypeWingetInstall.String(),
		AgentsType:  task.AgentTypeWindows.String(),
		PackageID:   "Git.Git",
		PackageName: "Git",
		Timeout:     120,
	}

	err = suite.model.AddTaskToProfile(c, p.ID, cfg)
	assert.NoError(suite.T(), err)

	createdTask, err := suite.model.Client.Task.Query().Where(task.HasProfileWith()).First(ctx)
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), 120, createdTask.Timeout)
	assert.Equal(suite.T(), "Install Winget package", createdTask.Name)

	// 3. Update task timeout
	cfg.Timeout = 300
	cfg.Description = "Updated Task"
	err = suite.model.UpdateProfileTask(c, createdTask.ID, cfg)
	assert.NoError(suite.T(), err)

	updatedTask, err := suite.model.Client.Task.Get(ctx, createdTask.ID)
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), 300, updatedTask.Timeout)
	assert.Equal(suite.T(), "Updated Task", updatedTask.Name)

	// 4. Clone task and verify timeout is copied
	err = suite.model.CloneTask(createdTask.ID, "Cloned Task", p.ID, 2)
	assert.NoError(suite.T(), err)

	clonedTask, err := suite.model.Client.Task.Query().Where(task.Name("Cloned Task")).First(ctx)
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), 300, clonedTask.Timeout)

	// 5. Create an agent and profile issue with task reports
	ag, err := suite.model.Client.Agent.Create().
		SetID("agent-1").
		SetHostname("host1").
		SetOs("windows").
		SetNickname("workstation-1").
		SetAgentStatus(agent.AgentStatusEnabled).
		Save(ctx)
	assert.NoError(suite.T(), err)

	issue, err := suite.model.Client.ProfileIssue.Create().
		SetProfile(p).
		SetAgents(ag).
		SetWhen(time.Now()).
		Save(ctx)
	assert.NoError(suite.T(), err)

	report1, err := suite.model.Client.TaskReport.Create().
		SetTask(createdTask).
		SetProfileissue(issue).
		SetStatus(taskreport.StatusRunning).
		SetStartedAt(time.Now().Add(-1 * time.Minute).Format(time.RFC3339Nano)).
		Save(ctx)
	assert.NoError(suite.T(), err)

	report2, err := suite.model.Client.TaskReport.Create().
		SetTask(createdTask).
		SetProfileissue(issue).
		SetStatus(taskreport.StatusFailed).
		SetTimeout(true).
		SetStartedAt(time.Now().Add(-5 * time.Minute).Format(time.RFC3339Nano)).
		SetEnd(time.Now().Add(-3 * time.Minute).Format(time.RFC3339Nano)).
		SetStdError("command timed out after 300 seconds").
		Save(ctx)
	assert.NoError(suite.T(), err)

	// 6. Test GetTaskExecutionReports
	reports, err := suite.model.GetTaskExecutionReports(createdTask.ID)
	assert.NoError(suite.T(), err)
	assert.Len(suite.T(), reports, 2)

	// Descending by StartedAt: report1 is newer than report2
	assert.Equal(suite.T(), report1.ID, reports[0].ID)
	assert.Equal(suite.T(), taskreport.StatusRunning, reports[0].Status)
	assert.NotNil(suite.T(), reports[0].Edges.Profileissue)
	assert.NotNil(suite.T(), reports[0].Edges.Profileissue.Edges.Agents)
	assert.Equal(suite.T(), "workstation-1", reports[0].Edges.Profileissue.Edges.Agents.Nickname)

	assert.Equal(suite.T(), report2.ID, reports[1].ID)
	assert.True(suite.T(), reports[1].Timeout)
	assert.Equal(suite.T(), taskreport.StatusFailed, reports[1].Status)
	assert.Equal(suite.T(), "command timed out after 300 seconds", reports[1].StdError)
}

func TestTasksTestSuite(t *testing.T) {
	s := new(TasksTestSuite)
	s.t = t
	suite.Run(t, s)
}
