using FluentCMS.Entities;
using FluentCMS.Repositories.Abstractions.Querying;

namespace FluentCMS.Repositories.Abstractions;

public interface IBaseEntityRepository<TEntity> where TEntity : BaseEntity
{
    Task<TEntity?> Create(TEntity entity, CancellationToken cancellationToken = default);
    Task<IEnumerable<TEntity>> CreateMany(IEnumerable<TEntity> entities, CancellationToken cancellationToken = default);
    Task<TEntity?> Update(TEntity entity, CancellationToken cancellationToken = default);
    Task<IEnumerable<TEntity>> UpdateMany(IEnumerable<TEntity> entities, CancellationToken cancellationToken = default);
    Task<TEntity?> Delete(Guid id, CancellationToken cancellationToken = default);
    Task<IEnumerable<TEntity>> DeleteMany(IEnumerable<Guid> ids, CancellationToken cancellationToken = default);
    Task<IEnumerable<TEntity>> GetAll(CancellationToken cancellationToken = default);
    Task<TEntity?> GetById(Guid id, CancellationToken cancellationToken = default);
    Task<IEnumerable<TEntity>> GetByIds(IEnumerable<Guid> ids, CancellationToken cancellationToken = default);
    Task<PagedResult<TEntity>> Query(QueryParameters<TEntity>? queryParameters = null, CancellationToken cancellationToken = default);
}
