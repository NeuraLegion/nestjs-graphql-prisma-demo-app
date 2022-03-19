import { Field, InputType } from '@nestjs/graphql';

import { ArticleUncheckedUpdateManyWithoutFavoritedByInput } from '../article/article-unchecked-update-many-without-favorited-by.input';
import { CommentUncheckedUpdateManyWithoutAuthorInput } from '../comment/comment-unchecked-update-many-without-author.input';
import { UserUncheckedUpdateManyWithoutFollowersInput } from './user-unchecked-update-many-without-followers.input';
import { UserUncheckedUpdateManyWithoutFollowingInput } from './user-unchecked-update-many-without-following.input';

@InputType()
export class UserUncheckedUpdateWithoutArticlesInput {
    @Field(() => String, { nullable: true })
    userId?: string;

    @Field(() => String, { nullable: true })
    email?: string;

    @Field(() => String, { nullable: true })
    name?: string;

    @Field(() => String, { nullable: true })
    password?: string;

    @Field(() => String, { nullable: true })
    bio?: string;

    @Field(() => String, { nullable: true })
    image?: string;

    @Field(() => UserUncheckedUpdateManyWithoutFollowersInput, { nullable: true })
    following?: UserUncheckedUpdateManyWithoutFollowersInput;

    @Field(() => UserUncheckedUpdateManyWithoutFollowingInput, { nullable: true })
    followers?: UserUncheckedUpdateManyWithoutFollowingInput;

    @Field(() => ArticleUncheckedUpdateManyWithoutFavoritedByInput, { nullable: true })
    favoriteArticles?: ArticleUncheckedUpdateManyWithoutFavoritedByInput;

    @Field(() => CommentUncheckedUpdateManyWithoutAuthorInput, { nullable: true })
    comments?: CommentUncheckedUpdateManyWithoutAuthorInput;
}
