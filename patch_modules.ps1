$xaml = Get-Content 'MainWindow.xaml' -Raw -Encoding UTF8

# 1. Subtitle x:Name
$xaml = $xaml -replace '(<TextBlock) (Text=" / NFA automata)', '$1 x:Name="ModulesSubtitle" $2'

# 2. Reload all button
$xaml = $xaml -replace 'Style="\{StaticResource BtnGhost\}" Margin="0,0,6,0">Reload all</Button>',
    'x:Name="BtnReloadAllModules" Style="{StaticResource BtnGhost}" Margin="0,0,6,0" Click="BtnReloadAllModules_Click">Reload all</Button>'

# 3. Import Module button
$xaml = $xaml -replace 'Style="\{StaticResource BtnAccent\}">Import Module</Button>',
    'x:Name="BtnImportModule" Style="{StaticResource BtnAccent}" Click="BtnImportModule_Click">Import Module</Button>'

# 4. Replace entire UniformGrid content with empty WrapPanel
# Match from <UniformGrid Columns="3" Margin="16"> ... </UniformGrid>
$xaml = $xaml -replace '(?s)<UniformGrid Columns="3" Margin="16">.*?</UniformGrid>',
    '<WrapPanel x:Name="ModulesGrid" Margin="16" Orientation="Horizontal"/>'

[System.IO.File]::WriteAllText('MainWindow.xaml', $xaml, [System.Text.Encoding]::UTF8)

Write-Host "Done. Checking:"
Write-Host "  ModulesSubtitle: $(($xaml -match 'ModulesSubtitle'))"
Write-Host "  BtnReloadAllModules: $(($xaml -match 'BtnReloadAllModules'))"
Write-Host "  BtnImportModule: $(($xaml -match 'BtnImportModule'))"
Write-Host "  ModulesGrid WrapPanel: $(($xaml -match 'ModulesGrid'))"
Write-Host "  UniformGrid gone: $(-not ($xaml -match 'Columns=""3"" Margin=""16""'))"
