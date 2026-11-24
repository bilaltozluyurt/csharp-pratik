// Runner: commit ettiğin görevleri numarasıyla çalıştırır.
//   dotnet run --project solutions          -> görevleri listeler
//   dotnet run --project solutions -- 41    -> 41 numaralı görevi çalıştırır
using System.Reflection;
using System.Runtime.ExceptionServices;

var tasks = typeof(Program).Assembly.GetTypes()
    .Where(x => x.IsClass && x.IsAbstract && x.IsSealed            // static class
             && x.Name.Length > 2 && x.Name[0] == 'G' && char.IsDigit(x.Name[1])
             && x.Name.Contains('_'))
    .Select(x => (No: int.Parse(x.Name[1..x.Name.IndexOf('_')]), Type: x))
    .OrderBy(x => x.No)
    .ToList();

if (args.Length == 0 || !int.TryParse(args[0], out var no))
{
    Console.WriteLine("Kullanım: dotnet run --project solutions -- <görev no>");
    Console.WriteLine(tasks.Count == 0 ? "Henüz commit edilmiş görev yok." : "Mevcut görevler:");
    foreach (var item in tasks)
        Console.WriteLine($"  {item.No,3}  {item.Type.Name}");
    return;
}

var target = tasks.FirstOrDefault(x => x.No == no);
if (target.Type is null)
{
    Console.WriteLine($"Görev {no} bulunamadı. Önce git pull yaptın mı?");
    return;
}

var run = target.Type.GetMethod("Run", BindingFlags.Public | BindingFlags.Static);
if (run is null)
{
    Console.WriteLine($"{target.Type.Name} içinde public static Run() metodu yok.");
    return;
}

Console.WriteLine($"=== Görev {no}: {target.Type.Name} ===\n");
try
{
    var result = run.Invoke(null, null);
    if (result is Task task) await task;
}
catch (TargetInvocationException ex) when (ex.InnerException is not null)
{
    ExceptionDispatchInfo.Capture(ex.InnerException).Throw();
}
