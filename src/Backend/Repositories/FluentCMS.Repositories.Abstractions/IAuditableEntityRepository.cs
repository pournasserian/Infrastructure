using FluentCMS.Entities;

namespace FluentCMS.Repositories.Abstractions;

public interface IAuditableEntityRepository<TEntity> : IBaseEntityRepository<TEntity> where TEntity : AuditableEntity
{

}
