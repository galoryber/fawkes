from mythic_container.MythicCommandBase import *


class ListEntitlementsArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="pid",
                type=ParameterType.Number,
                default_value=-1,
                description="Pid of the process to enumerate (-1 for all processes)",
                parameter_group_info=[ParameterGroupInfo(
                    required=False
                )]
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise ValueError("Must supply a path to a file")
        self.add_arg("pid", int(self.command_line))

    async def parse_dictionary(self, dictionary_arguments):
        if "pid" in dictionary_arguments:
            self.add_arg("pid", dictionary_arguments["pid"])


class ListEntitlementsCommand(CommandBase):
    cmd = "list_entitlements"
    needs_admin = False
    help_cmd = 'list_entitlements [pid]'
    description = "This uses JXA to list the entitlements for a running process"
    version = 1
    author = "@its_a_feature_"
    attackmapping = ["T1057"]
    argument_class = ListEntitlementsArguments
    supported_ui_features = ["list_entitlements:list"]
    browser_script = BrowserScript(script_name="list_entitlements_new", author="@its_a_feature_", for_new_ui=True)

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        if taskData.args.get_arg("pid") == -1:
            response.DisplayParams = "for all running applications"
        else:
            response.DisplayParams = "for pid " + str(taskData.args.get_arg("pid"))
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp
