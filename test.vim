function! SetSolution()
	let g:msbuild_sln = expand('%:p')
	"let g:msbuild_sln = expand('<cfile>:p')
	echo 'Current msbuild solution set to ' . g:msbuild_sln
endfunction()

function! SetCompilerForFile()
	let &makeprg = 'msbuild ' . g:msbuild_sln . ' /t:clcompile /p:selectedfiles="' . expand('%:p') . '"' . ' /nologo /v:q /property:generatefullpaths=true ' 
	set errorformat=%f(%l):\ %m
endfunction()

function! SetBuildAll()
	let &makeprg = 'msbuild ' . g:msbuild_sln . ' /nologo /v:q /property:generatefullpaths=true ' 
	set errorformat=%f(%l):\ %m
endfunction()

nnoremap <C-F7> :call SetCompilerForFile()<CR>:make<CR>
nnoremap <F7> :call SetBuildAll()<CR>:make<CR>

