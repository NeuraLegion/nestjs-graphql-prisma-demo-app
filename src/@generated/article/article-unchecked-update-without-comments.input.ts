import { Field, InputType, Int } from '@nestjs/graphql';

import { TagUncheckedUpdateManyWithoutArticlesInput } from '../tag/tag-unchecked-update-many-without-articles.input';
import { UserUncheckedUpdateManyWithoutFavoriteArticlesInput } from '../user/user-unchecked-update-many-without-favorite-articles.input';

@InputType()
export class ArticleUncheckedUpdateWithoutCommentsInput {
    @Field(() => String, { nullable: true })
    articleId?: string;

    @Field(() => String, { nullable: true })
    slug?: string;

    @Field(() => String, { nullable: true })
    title?: string;

    @Field(() => String, { nullable: true })
    description?: string;

    @Field(() => String, { nullable: true })
    body?: string;

    @Field(() => TagUncheckedUpdateManyWithoutArticlesInput, { nullable: true })
    tags?: TagUncheckedUpdateManyWithoutArticlesInput;

    @Field(() => Date, { nullable: true })
    createdAt?: Date | string;

    @Field(() => Date, { nullable: true })
    updatedAt?: Date | string;

    @Field(() => Int, { nullable: true })
    favoritesCount?: number;

    @Field(() => String, { nullable: true })
    authorId?: string;

    @Field(() => UserUncheckedUpdateManyWithoutFavoriteArticlesInput, {
        nullable: true,
    })
    favoritedBy?: UserUncheckedUpdateManyWithoutFavoriteArticlesInput;
}
