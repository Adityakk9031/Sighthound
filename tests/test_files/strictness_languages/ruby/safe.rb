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

  # Multi-argument / Array forms with env and options hashes (still safe)
  system({"ENV_VAR" => "val"}, "ls", params[:cmd]) # Safe because multi-argument with env hash
  system("ls", params[:cmd], {chdir: "/tmp"}) # Safe because multi-argument with options hash
  system({"ENV_VAR" => "val"}, "ls", params[:cmd], {chdir: "/tmp"}) # Safe because multi-argument with env and options hash
  system({"ENV_VAR" => "val"}, ["ls", params[:cmd]]) # Safe because array literal with env hash
  system(["ls", params[:cmd]], {chdir: "/tmp"}) # Safe because array literal with options hash
  system({"ENV_VAR" => "val"}, ["ls", params[:cmd]], {chdir: "/tmp"}) # Safe because array literal with env and options hash
  
  User.where("id = ?", params[:id].to_i)
end
