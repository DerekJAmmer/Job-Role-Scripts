@{
    Severity     = @('Error', 'Warning')
    IncludeRules = @('PSAvoidUsingCmdletAliases',
                     'PSAvoidUsingPositionalParameters',
                     'PSUseApprovedVerbs',
                     'PSUseDeclaredVarsMoreThanAssignments',
                     'PSAvoidUsingWriteHost',
                     'PSUseShouldProcessForStateChangingFunctions',
                     'PSAvoidUsingPlainTextForPassword',
                     'PSAvoidUsingConvertToSecureStringWithPlainText',
                     'PSAvoidUsingInvokeExpression',
                     'PSUseCmdletCorrectly',
                     'PSUseSingularNouns',
                     'PSProvideCommentHelp')
    ExcludeRules = @()
    Rules        = @{
        PSProvideCommentHelp = @{
            Enable             = $true
            ExportedOnly       = $true
            BlockComment       = $true
            VSCodeSnippetCorrection = $false
            Placement          = 'before'
        }
    }
}
