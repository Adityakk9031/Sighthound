require "shellwords"

def safe(params)
  system("ls", Shellwords.escape(params[:cmd]))
  system("ls", params[:cmd]) # Safe because multi-argument (bypasses shell)
  system(["ls", params[:cmd]]) # Safe because array literal (bypasses shell)
  system(*["ls", params[:cmd]]) # Safe because splatted array literal (bypasses shell)
  exec("ls", params[:cmd]) # Safe because multi-argument
  exec(["ls", params[:cmd]]) # Safe because array literal
  spawn("ls", params[:cmd]) # Safe because multi-argument
  spawn(["ls", params[:cmd]]) # Safe because array literal
  Open3.capture2("ls", params[:cmd]) # Safe because multi-argument
  IO.popen(["ls", params[:cmd]]) # Safe because array literal
  
  User.where("id = ?", params[:id].to_i)
end
